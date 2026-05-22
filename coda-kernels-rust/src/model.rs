//! A tiny **LLaMA-style Transformer** built on the CODA kernels.
//!
//! The decoder layer is pre-normalized with RMSNorm, uses rotary position
//! embeddings on Q/K, causal self-attention, and a SwiGLU MLP - the
//! "Transformer++" architecture the CODA paper targets.
//!
//! The whole non-attention forward pass is expressed as the
//! **GEMM-Residual-RMSNorm-GEMM** chain of paper §3.2.1. Crucially, the
//! residual add and the RMSNorm of one sublayer are fused into the *epilogue
//! of the previous sublayer's output projection*: the row-wise factor `r`
//! commutes with the next GEMM, so it is applied in that GEMM's epilogue
//! ([`kernels::gemm_rmsnorm`]) rather than as a standalone normalization.
//!
//! Two forward paths are provided:
//! * [`Model::forward`] - the fused CODA path (kernels 4/5/6).
//! * [`Model::forward_ref`] - the naive unfused operator sequence.
//!
//! They are numerically equivalent; the difference is DRAM traffic, which the
//! demo measures.

use crate::kernels;
use crate::reference as rf;
use crate::tensor::{self, Mat};

/// A minimal deterministic PRNG (xorshift128+) so the demo needs no crates.
pub struct Rng {
    s0: u64,
    s1: u64,
}

impl Rng {
    /// Seed the generator.
    pub fn new(seed: u64) -> Rng {
        Rng { s0: seed ^ 0x9E3779B97F4A7C15, s1: seed.wrapping_mul(0xD1B54A32D192ED03) | 1 }
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.s0;
        let y = self.s1;
        self.s0 = y;
        x ^= x << 23;
        self.s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        self.s1.wrapping_add(y)
    }
    /// Uniform `f32` in `[0, 1)`.
    pub fn uniform(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
    /// Approximately standard-normal `f32` (sum of 6 uniforms, mean-centered).
    pub fn normal(&mut self) -> f32 {
        let mut s = 0.0f32;
        for _ in 0..6 {
            s += self.uniform();
        }
        (s - 3.0) * 0.7071
    }
}

/// Model hyper-parameters.
#[derive(Clone, Debug)]
pub struct Config {
    pub vocab: usize,
    pub d_model: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub head_dim: usize,
    /// SwiGLU hidden width (per gate/up branch); the gate/up GEMM emits `2 * d_ff`.
    pub d_ff: usize,
    pub eps: f32,
    pub rope_base: f32,
}

impl Config {
    /// The tiny configuration used by the CPU demo.
    pub fn tiny(vocab: usize) -> Config {
        Config {
            vocab,
            d_model: 64,
            n_layers: 2,
            n_heads: 2,
            head_dim: 32,
            d_ff: 128,
            eps: 1e-5,
            rope_base: 10000.0,
        }
    }
}

/// Per-layer weights.
#[derive(Clone)]
pub struct Layer {
    /// RMSNorm weight before attention, `[d_model]`.
    pub gamma_attn: Vec<f32>,
    /// Fused QKV projection, `[d_model, 3 * d_model]`.
    pub wqkv: Mat,
    /// Attention output projection, `[d_model, d_model]`.
    pub wo: Mat,
    /// RMSNorm weight before the MLP, `[d_model]`.
    pub gamma_ffn: Vec<f32>,
    /// SwiGLU gate/up projection, `[d_model, 2 * d_ff]`.
    pub wgu: Mat,
    /// MLP down projection, `[d_ff, d_model]`.
    pub wdown: Mat,
}

/// The full model.
#[derive(Clone)]
pub struct Model {
    pub cfg: Config,
    /// Token embedding table, `[vocab, d_model]`.
    pub embed: Mat,
    pub layers: Vec<Layer>,
    /// Final RMSNorm weight, `[d_model]`.
    pub gamma_final: Vec<f32>,
    /// Language-modeling head, `[d_model, vocab]`.
    pub lm_head: Mat,
}

/// Saved activations for one layer (the canonical computation graph, used by
/// the backward pass in [`crate::train`]).
#[derive(Clone)]
pub struct LayerCache {
    pub x_resid: Mat,
    pub r1: Vec<f32>,
    pub qkv: Mat,
    pub q_rot: Mat,
    pub k_rot: Mat,
    pub v: Mat,
    pub probs: Vec<Mat>,
    pub attn_out: Mat,
    pub h: Mat,
    pub r2: Vec<f32>,
    pub gu: Mat,
    pub ff: Mat,
}

/// Saved activations for the whole forward pass.
#[derive(Clone)]
pub struct Cache {
    pub tokens: Vec<usize>,
    pub layers: Vec<LayerCache>,
    pub y_final: Mat,
    pub rf: Vec<f32>,
    pub logits: Mat,
}

/// A random `[rows, cols]` matrix scaled by `scale`.
fn randn(rng: &mut Rng, rows: usize, cols: usize, scale: f32) -> Mat {
    let mut m = Mat::zeros(rows, cols);
    for v in m.data.iter_mut() {
        *v = rng.normal() * scale;
    }
    m
}

impl Model {
    /// Initialize a model with small random weights.
    pub fn new(cfg: Config, rng: &mut Rng) -> Model {
        let d = cfg.d_model;
        let embed = randn(rng, cfg.vocab, d, 0.08);
        let mut layers = Vec::new();
        for _ in 0..cfg.n_layers {
            // 1/sqrt(fan_in) style initialization.
            let s_in = 1.0 / (d as f32).sqrt();
            let s_ff = 1.0 / (cfg.d_ff as f32).sqrt();
            layers.push(Layer {
                gamma_attn: vec![1.0; d],
                wqkv: randn(rng, d, 3 * d, s_in),
                wo: randn(rng, d, d, s_in),
                gamma_ffn: vec![1.0; d],
                wgu: randn(rng, d, 2 * cfg.d_ff, s_in),
                wdown: randn(rng, cfg.d_ff, d, s_ff),
            });
        }
        let lm_head = randn(rng, d, cfg.vocab, 1.0 / (d as f32).sqrt());
        Model { cfg, embed, layers, gamma_final: vec![1.0; d], lm_head }
    }

    /// Embedding lookup `[T, d_model]` for a token sequence.
    pub fn embed_tokens(&self, tokens: &[usize]) -> Mat {
        let d = self.cfg.d_model;
        let mut x = Mat::zeros(tokens.len(), d);
        for (i, &t) in tokens.iter().enumerate() {
            x.row_mut(i).copy_from_slice(self.embed.row(t));
        }
        tensor::account_elems(tokens.len() * d); // gather from the embedding table
        x
    }

    /// Precompute the RoPE `cos` / `sin` tables of shape `[T, d_model]`.
    pub fn rope_tables(&self, t: usize) -> (Mat, Mat) {
        let (d, hd, nh) = (self.cfg.d_model, self.cfg.head_dim, self.cfg.n_heads);
        let mut cos = Mat::zeros(t, d);
        let mut sin = Mat::zeros(t, d);
        for pos in 0..t {
            for h in 0..nh {
                for p in 0..hd / 2 {
                    let freq = self.cfg.rope_base.powf(-2.0 * p as f32 / hd as f32);
                    let ang = pos as f32 * freq;
                    let (c, s) = (ang.cos(), ang.sin());
                    let base = h * hd + 2 * p;
                    cos.set(pos, base, c);
                    cos.set(pos, base + 1, c);
                    sin.set(pos, base, s);
                    sin.set(pos, base + 1, s);
                }
            }
        }
        (cos, sin)
    }
}

/// Row-wise RMS normalization factor `r[i] = 1 / sqrt(mean(x[i]^2) + eps)`.
pub fn rms_factor(x: &Mat, eps: f32) -> Vec<f32> {
    let mut r = vec![0.0f32; x.rows];
    for i in 0..x.rows {
        let mut sq = 0.0f32;
        for j in 0..x.cols {
            let v = x.get(i, j);
            sq += v * v;
        }
        r[i] = 1.0 / (sq / x.cols as f32 + eps).sqrt();
    }
    r
}

/// Multiply each column `j` of `x` by `gamma[j]` (the RMSNorm weight applied
/// before the projection - paper Kernel 4's `O = D ⊙ γ`).
pub fn col_scale(x: &Mat, gamma: &[f32]) -> Mat {
    let mut out = Mat::zeros(x.rows, x.cols);
    for i in 0..x.rows {
        for j in 0..x.cols {
            out.set(i, j, x.get(i, j) * gamma[j]);
        }
    }
    out
}

/// The embedding-side RMSNorm preparation: returns `(o_norm, r)` where
/// `o_norm = x ⊙ γ` and `r` is the row-wise inverse RMS factor of `x`.
///
/// This is the one normalization CODA does *not* fuse - the paper excludes
/// embeddings from the GEMM-plus-epilogue reparameterization (§5). Every later
/// RMSNorm is subsumed into a Kernel 4 epilogue. This op is accounted as
/// global-memory traffic in both forward paths.
pub fn input_norm(x: &Mat, gamma: &[f32], eps: f32) -> (Mat, Vec<f32>) {
    tensor::account_read(x);
    tensor::account_elems(gamma.len());
    let r = rms_factor(x, eps);
    let o_norm = col_scale(x, gamma);
    tensor::account_write(&o_norm);
    (o_norm, r)
}

/// Causal scaled-dot-product self-attention.
///
/// Attention is explicitly *outside* CODA's scope (paper §5), so it is the
/// same plain implementation in both forward paths and does not bias the
/// traffic comparison. Returns `(output[T, d_model], per-head softmax probs)`.
pub fn attention(
    q: &Mat,
    k: &Mat,
    v: &Mat,
    n_heads: usize,
    head_dim: usize,
) -> (Mat, Vec<Mat>) {
    let t = q.rows;
    let scale = 1.0 / (head_dim as f32).sqrt();
    let mut out = Mat::zeros(t, n_heads * head_dim);
    let mut all_probs = Vec::with_capacity(n_heads);
    tensor::account_read(q);
    tensor::account_read(k);
    tensor::account_read(v);
    for h in 0..n_heads {
        let off = h * head_dim;
        let mut probs = Mat::zeros(t, t);
        for i in 0..t {
            // Scores against all non-future positions.
            let mut mx = f32::NEG_INFINITY;
            let mut score = vec![f32::NEG_INFINITY; t];
            for j in 0..=i {
                let mut s = 0.0f32;
                for d in 0..head_dim {
                    s += q.get(i, off + d) * k.get(j, off + d);
                }
                s *= scale;
                score[j] = s;
                mx = mx.max(s);
            }
            let mut se = 0.0f32;
            for j in 0..=i {
                let e = (score[j] - mx).exp();
                score[j] = e;
                se += e;
            }
            for j in 0..=i {
                let p = score[j] / se;
                probs.set(i, j, p);
                for d in 0..head_dim {
                    out.add(i, off + d, p * v.get(j, off + d));
                }
            }
        }
        all_probs.push(probs);
    }
    tensor::account_write(&out);
    (out, all_probs)
}

impl Model {
    /// The **CODA forward pass**: the non-attention computation is the fused
    /// GEMM-Residual-RMSNorm-GEMM chain of paper §3.2.1. Returns
    /// `(logits, cache)`.
    ///
    /// The pair `(o_norm, r)` is threaded across the whole network: each
    /// Kernel 4 emits the *next* sublayer's `o_norm = D ⊙ γ` as a side output
    /// and the auxiliary reduction yields its `r`. The next GEMM applies `r`
    /// in its own epilogue (delayed-scale trick). No standalone RMSNorm kernel
    /// runs anywhere except the embedding-side [`input_norm`].
    pub fn forward(&self, tokens: &[usize]) -> (Mat, Cache) {
        let cfg = &self.cfg;
        let t = tokens.len();
        let d = cfg.d_model;
        let x0 = self.embed_tokens(tokens);
        let (cos, sin) = self.rope_tables(t);

        // Embedding-side RMSNorm: the only normalization not fused into a GEMM.
        let (mut o_norm, mut r) = input_norm(&x0, &self.layers[0].gamma_attn, cfg.eps);
        let mut x_resid = x0;
        let mut layers_cache = Vec::with_capacity(cfg.n_layers);

        for l in 0..cfg.n_layers {
            let layer = &self.layers[l];

            // --- QKV projection with the delayed RMSNorm scale (Kernel 5). ---
            let qkv = kernels::gemm_rmsnorm(&o_norm, &layer.wqkv, &r);

            // Split QKV and apply RoPE to Q and K.
            let (mut q, mut k, mut v) = (Mat::zeros(t, d), Mat::zeros(t, d), Mat::zeros(t, d));
            for i in 0..t {
                q.row_mut(i).copy_from_slice(&qkv.row(i)[0..d]);
                k.row_mut(i).copy_from_slice(&qkv.row(i)[d..2 * d]);
                v.row_mut(i).copy_from_slice(&qkv.row(i)[2 * d..3 * d]);
            }
            let q_rot = rf::rope(&q, &cos, &sin);
            let k_rot = rf::rope(&k, &cos, &sin);

            // --- Attention (outside CODA scope). ---
            let (attn_out, probs) = attention(&q_rot, &k_rot, &v, cfg.n_heads, cfg.head_dim);

            // --- Output proj + residual + FFN-norm (Kernel 4). ---
            // h = attn_out @ Wo + x_resid ; n2 = h ⊙ γ_ffn ; r2 = rms of h.
            let (h, n2, r2) = kernels::gemm_residual_partial_rms(
                &attn_out,
                &layer.wo,
                &x_resid,
                &layer.gamma_ffn,
                cfg.eps,
            );

            // --- Gate/Up projection + SwiGLU (Kernel 6); gu is saved. ---
            let (ff, gu) = kernels::gemm_rmsnorm_swiglu(&n2, &layer.wgu, &r2);

            // --- Down proj + residual + next sublayer's norm (Kernel 4). ---
            let next_gamma = if l + 1 < cfg.n_layers {
                &self.layers[l + 1].gamma_attn
            } else {
                &self.gamma_final
            };
            let (y, next_o_norm, r_next) =
                kernels::gemm_residual_partial_rms(&ff, &layer.wdown, &h, next_gamma, cfg.eps);

            layers_cache.push(LayerCache {
                x_resid: x_resid.clone(),
                r1: r.clone(),
                qkv,
                q_rot,
                k_rot,
                v,
                probs,
                attn_out,
                h,
                r2,
                gu,
                ff,
            });
            // Thread the next sublayer's normalized input and factor.
            x_resid = y;
            o_norm = next_o_norm;
            r = r_next;
        }

        // --- Final RMSNorm (already fused as the last Kernel 4's O) + LM head. ---
        let y_final = x_resid;
        let logits = kernels::gemm_rmsnorm(&o_norm, &self.lm_head, &r);

        let cache = Cache {
            tokens: tokens.to_vec(),
            layers: layers_cache,
            y_final,
            rf: r,
            logits: logits.clone(),
        };
        (logits, cache)
    }

    /// The **naive unfused forward pass**: identical math, but every operator
    /// materializes its output to global memory. Used as the traffic baseline
    /// and as an independent correctness reference.
    pub fn forward_ref(&self, tokens: &[usize]) -> Mat {
        let cfg = &self.cfg;
        let t = tokens.len();
        let mut x = self.embed_tokens(tokens);
        let (cos, sin) = self.rope_tables(t);

        for layer in &self.layers {
            // RMSNorm -> QKV projection.
            let (n1, _) = rf::rmsnorm(&x, &layer.gamma_attn, cfg.eps);
            let qkv = rf::gemm(&n1, false, &layer.wqkv, false);
            let d = cfg.d_model;
            let (mut q, mut k, mut v) = (Mat::zeros(t, d), Mat::zeros(t, d), Mat::zeros(t, d));
            for i in 0..t {
                q.row_mut(i).copy_from_slice(&qkv.row(i)[0..d]);
                k.row_mut(i).copy_from_slice(&qkv.row(i)[d..2 * d]);
                v.row_mut(i).copy_from_slice(&qkv.row(i)[2 * d..3 * d]);
            }
            let q_rot = rf::rope(&q, &cos, &sin);
            let k_rot = rf::rope(&k, &cos, &sin);
            let (attn_out, _) = attention(&q_rot, &k_rot, &v, cfg.n_heads, cfg.head_dim);

            // Output proj -> residual.
            let ao = rf::gemm(&attn_out, false, &layer.wo, false);
            let h = rf::residual(&ao, &x);

            // RMSNorm -> gate/up -> SwiGLU -> down -> residual.
            let (n2, _) = rf::rmsnorm(&h, &layer.gamma_ffn, cfg.eps);
            let gu = rf::gemm(&n2, false, &layer.wgu, false);
            let ff = rf::swiglu(&gu);
            let dn = rf::gemm(&ff, false, &layer.wdown, false);
            x = rf::residual(&dn, &h);
        }

        let (nf, _) = rf::rmsnorm(&x, &self.gamma_final, cfg.eps);
        rf::gemm(&nf, false, &self.lm_head, false)
    }

    /// Greedy autoregressive generation: extend `prompt` by `n` tokens.
    pub fn generate(&self, prompt: &[usize], n: usize) -> Vec<usize> {
        let mut seq = prompt.to_vec();
        for _ in 0..n {
            let (logits, _) = self.forward(&seq);
            let last = logits.rows - 1;
            let mut best = 0usize;
            let mut best_v = f32::NEG_INFINITY;
            for j in 0..logits.cols {
                if logits.get(last, j) > best_v {
                    best_v = logits.get(last, j);
                    best = j;
                }
            }
            seq.push(best);
        }
        seq
    }
}
