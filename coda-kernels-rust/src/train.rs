//! The **backward pass**, an Adam optimizer, and the training loop.
//!
//! Per CODA's Theorem 1 (paper §3.2.4), a forward pass built from
//! GEMM-with-epilogue blocks has a backward pass with the *same* structure:
//! `GEMM, tile-local transform, GEMM`. The component backward rules below are
//! exactly those tile-local transforms - in particular [`swiglu_bwd`] is the
//! epilogue of Kernel 10 and [`rmsnorm_bwd`] is the local part of Kernel 9.
//! The surrounding linear maps are plain GEMMs ([`kernels::gemm`]).

use crate::epilogue::{sigmoid, silu};
use crate::kernels;
use crate::model::{col_scale, Cache, Model};
use crate::tensor::Mat;

// ---------------------------------------------------------------------------
// Gradient containers.
// ---------------------------------------------------------------------------

/// Gradients for one layer's weights.
#[derive(Clone)]
pub struct LayerGrad {
    pub d_gamma_attn: Vec<f32>,
    pub d_wqkv: Mat,
    pub d_wo: Mat,
    pub d_gamma_ffn: Vec<f32>,
    pub d_wgu: Mat,
    pub d_wdown: Mat,
}

/// Gradients for the whole model.
#[derive(Clone)]
pub struct Grads {
    pub d_embed: Mat,
    pub layers: Vec<LayerGrad>,
    pub d_gamma_final: Vec<f32>,
    pub d_lm_head: Mat,
}

impl Grads {
    /// All gradient buffers as flat slices, in the canonical parameter order
    /// (must match [`Model::params_mut`]).
    pub fn flat(&self) -> Vec<&[f32]> {
        let mut v: Vec<&[f32]> = vec![self.d_embed.data.as_slice()];
        for lg in &self.layers {
            v.push(&lg.d_gamma_attn);
            v.push(lg.d_wqkv.data.as_slice());
            v.push(lg.d_wo.data.as_slice());
            v.push(&lg.d_gamma_ffn);
            v.push(lg.d_wgu.data.as_slice());
            v.push(lg.d_wdown.data.as_slice());
        }
        v.push(&self.d_gamma_final);
        v.push(self.d_lm_head.data.as_slice());
        v
    }
}

impl Model {
    /// Mutable views of every parameter, in the canonical order.
    pub fn params_mut(&mut self) -> Vec<&mut [f32]> {
        let mut v: Vec<&mut [f32]> = vec![self.embed.data.as_mut_slice()];
        for layer in self.layers.iter_mut() {
            v.push(layer.gamma_attn.as_mut_slice());
            v.push(layer.wqkv.data.as_mut_slice());
            v.push(layer.wo.data.as_mut_slice());
            v.push(layer.gamma_ffn.as_mut_slice());
            v.push(layer.wgu.data.as_mut_slice());
            v.push(layer.wdown.data.as_mut_slice());
        }
        v.push(self.gamma_final.as_mut_slice());
        v.push(self.lm_head.data.as_mut_slice());
        v
    }
}

// ---------------------------------------------------------------------------
// Component backward rules (the tile-local epilogues of Theorem 1).
// ---------------------------------------------------------------------------

/// RMSNorm backward (the local rule of Kernel 9). `d_n` is the gradient of
/// `rmsnorm(x) ⊙ γ`; returns `(d_x, d_γ)`.
pub fn rmsnorm_bwd(x: &Mat, r: &[f32], gamma: &[f32], d_n: &Mat) -> (Mat, Vec<f32>) {
    let d = x.cols;
    let mut d_x = Mat::zeros(x.rows, x.cols);
    let mut d_gamma = vec![0.0f32; d];
    for i in 0..x.rows {
        let ri = r[i];
        let mut s = 0.0f32; // S = Σ_j d_nrm[j] * x[j]
        for j in 0..d {
            let d_nrm = d_n.get(i, j) * gamma[j];
            s += d_nrm * x.get(i, j);
            d_gamma[j] += d_n.get(i, j) * (x.get(i, j) * ri);
        }
        let r3 = ri * ri * ri;
        for j in 0..d {
            let d_nrm = d_n.get(i, j) * gamma[j];
            d_x.set(i, j, ri * d_nrm - (r3 / d as f32) * x.get(i, j) * s);
        }
    }
    (d_x, d_gamma)
}

/// SwiGLU backward (the epilogue of Kernel 10). `gu` is the interleaved
/// pre-activation `[G, U]`; `d_ff` is the gradient of `silu(G) ⊙ U`. Returns
/// the gradient w.r.t. `gu`.
pub fn swiglu_bwd(gu: &Mat, d_ff: &Mat) -> Mat {
    let mut d_gu = Mat::zeros(gu.rows, gu.cols);
    for i in 0..gu.rows {
        for k in 0..d_ff.cols {
            let g = gu.get(i, 2 * k);
            let u = gu.get(i, 2 * k + 1);
            let d_o = d_ff.get(i, k);
            let sg = silu(g);
            let sig = sigmoid(g);
            let d_silu = sig + sg * (1.0 - sig); // silu'(g)
            d_gu.set(i, 2 * k, d_o * u * d_silu);
            d_gu.set(i, 2 * k + 1, d_o * sg);
        }
    }
    d_gu
}

/// RoPE backward: the rotation Jacobian is orthogonal, so the backward rule is
/// the rotation by the negated angle.
pub fn rope_bwd(d_out: &Mat, cos: &Mat, sin: &Mat) -> Mat {
    let mut d_in = Mat::zeros(d_out.rows, d_out.cols);
    for i in 0..d_out.rows {
        let mut j = 0;
        while j < d_out.cols {
            let g0 = d_out.get(i, j);
            let g1 = d_out.get(i, j + 1);
            let c = cos.get(i, j);
            let s = sin.get(i, j);
            d_in.set(i, j, g0 * c + g1 * s);
            d_in.set(i, j + 1, -g0 * s + g1 * c);
            j += 2;
        }
    }
    d_in
}

/// Causal attention backward. Returns `(d_q, d_k, d_v)`.
pub fn attention_bwd(
    q: &Mat,
    k: &Mat,
    v: &Mat,
    probs: &[Mat],
    d_out: &Mat,
    n_heads: usize,
    head_dim: usize,
) -> (Mat, Mat, Mat) {
    let t = q.rows;
    let scale = 1.0 / (head_dim as f32).sqrt();
    let mut d_q = Mat::zeros(t, n_heads * head_dim);
    let mut d_k = Mat::zeros(t, n_heads * head_dim);
    let mut d_v = Mat::zeros(t, n_heads * head_dim);
    for h in 0..n_heads {
        let off = h * head_dim;
        let p = &probs[h];
        for i in 0..t {
            // d_p[i, j] = d_out[i] . v[j]   and   Σ_j p[i,j] d_p[i,j].
            let mut dp = vec![0.0f32; i + 1];
            let mut dotsum = 0.0f32;
            for (j, dpj) in dp.iter_mut().enumerate() {
                let mut s = 0.0f32;
                for d in 0..head_dim {
                    s += d_out.get(i, off + d) * v.get(j, off + d);
                }
                *dpj = s;
                dotsum += p.get(i, j) * s;
            }
            for j in 0..=i {
                // softmax backward -> gradient on the (scaled) score.
                let d_score = p.get(i, j) * (dp[j] - dotsum);
                let pij = p.get(i, j);
                for d in 0..head_dim {
                    d_v.add(j, off + d, pij * d_out.get(i, off + d));
                    d_q.add(i, off + d, scale * d_score * k.get(j, off + d));
                    d_k.add(j, off + d, scale * d_score * q.get(i, off + d));
                }
            }
        }
    }
    (d_q, d_k, d_v)
}

// ---------------------------------------------------------------------------
// Loss + full-model backward.
// ---------------------------------------------------------------------------

/// Row-wise softmax of `z`.
fn softmax_rows(z: &Mat) -> Mat {
    let mut p = Mat::zeros(z.rows, z.cols);
    for i in 0..z.rows {
        let mut mx = f32::NEG_INFINITY;
        for j in 0..z.cols {
            mx = mx.max(z.get(i, j));
        }
        let mut se = 0.0f32;
        for j in 0..z.cols {
            let e = (z.get(i, j) - mx).exp();
            p.set(i, j, e);
            se += e;
        }
        for j in 0..z.cols {
            p.set(i, j, p.get(i, j) / se);
        }
    }
    p
}

/// Mean cross-entropy loss over a sequence given the model logits.
pub fn mean_loss(logits: &Mat, targets: &[usize]) -> f32 {
    let p = softmax_rows(logits);
    let mut l = 0.0f32;
    for i in 0..logits.rows {
        l -= p.get(i, targets[i]).max(1e-30).ln();
    }
    l / logits.rows as f32
}

/// Convenience: forward the model and return the mean loss.
pub fn loss_of(model: &Model, tokens: &[usize], targets: &[usize]) -> f32 {
    let (logits, _) = model.forward(tokens);
    mean_loss(&logits, targets)
}

/// Full backward pass over the canonical computation graph. Returns
/// `(mean_loss, grads)`.
pub fn backward(model: &Model, cache: &Cache, targets: &[usize]) -> (f32, Grads) {
    let cfg = &model.cfg;
    let t = cache.tokens.len();
    let inv_t = 1.0 / t as f32;

    // --- Cross-entropy: d_logits = (softmax - onehot) / T. ---
    let probs = softmax_rows(&cache.logits);
    let mut loss = 0.0f32;
    let mut d_logits = probs.clone();
    for i in 0..t {
        loss -= probs.get(i, targets[i]).max(1e-30).ln();
        d_logits.add(i, targets[i], -1.0);
        for j in 0..cfg.vocab {
            d_logits.set(i, j, d_logits.get(i, j) * inv_t);
        }
    }
    loss *= inv_t;

    // --- LM head: logits = nf @ W_lm,  nf = rmsnorm(y_final) ⊙ γ_final. ---
    let nf = {
        let mut m = Mat::zeros(t, cfg.d_model);
        for i in 0..t {
            for j in 0..cfg.d_model {
                m.set(i, j, cache.y_final.get(i, j) * cache.rf[i] * model.gamma_final[j]);
            }
        }
        m
    };
    let d_lm_head = kernels::gemm(&nf, true, &d_logits, false);
    let d_nf = kernels::gemm(&d_logits, false, &model.lm_head, true);
    let (mut d_x, d_gamma_final) = rmsnorm_bwd(&cache.y_final, &cache.rf, &model.gamma_final, &d_nf);

    // --- Per-layer backward (reverse order). ---
    let mut layer_grads: Vec<LayerGrad> = Vec::with_capacity(cfg.n_layers);
    for l in (0..cfg.n_layers).rev() {
        let lc = &cache.layers[l];
        let layer = &model.layers[l];
        let d = cfg.d_model;

        // d_x is the gradient of this layer's residual-stream output y.
        let d_y = d_x;

        // y = dn + h  (residual).
        let d_dn = d_y.clone();
        let mut d_h = d_y;

        // dn = ff @ W_down.
        let d_ff = kernels::gemm(&d_dn, false, &layer.wdown, true);
        let d_wdown = kernels::gemm(&lc.ff, true, &d_dn, false);

        // ff = swiglu(gu).
        let d_gu = swiglu_bwd(&lc.gu, &d_ff);

        // gu = n2 @ W_gu,  n2 = rmsnorm(h) ⊙ γ_ffn.
        let n2 = col_scale_rms(&lc.h, &lc.r2, &layer.gamma_ffn);
        let d_wgu = kernels::gemm(&n2, true, &d_gu, false);
        let d_n2 = kernels::gemm(&d_gu, false, &layer.wgu, true);
        let (d_h2, d_gamma_ffn) = rmsnorm_bwd(&lc.h, &lc.r2, &layer.gamma_ffn, &d_n2);
        for i in 0..d_h.data.len() {
            d_h.data[i] += d_h2.data[i];
        }

        // h = attn_out @ W_o + x  (residual).
        let d_ao = d_h.clone();
        let d_wo = kernels::gemm(&lc.attn_out, true, &d_ao, false);
        let d_attn = kernels::gemm(&d_ao, false, &layer.wo, true);

        // attn_out = sdpa(q_rot, k_rot, v).
        let (d_q_rot, d_k_rot, d_v) =
            attention_bwd(&lc.q_rot, &lc.k_rot, &lc.v, &lc.probs, &d_attn, cfg.n_heads, cfg.head_dim);

        // q_rot = rope(q),  k_rot = rope(k).
        let (cos, sin) = model.rope_tables(t);
        let d_q = rope_bwd(&d_q_rot, &cos, &sin);
        let d_k = rope_bwd(&d_k_rot, &cos, &sin);

        // qkv = n1 @ W_qkv,  n1 = rmsnorm(x) ⊙ γ_attn.
        let mut d_qkv = Mat::zeros(t, 3 * d);
        for i in 0..t {
            d_qkv.row_mut(i)[0..d].copy_from_slice(d_q.row(i));
            d_qkv.row_mut(i)[d..2 * d].copy_from_slice(d_k.row(i));
            d_qkv.row_mut(i)[2 * d..3 * d].copy_from_slice(d_v.row(i));
        }
        let n1 = col_scale_rms(&lc.x_resid, &lc.r1, &layer.gamma_attn);
        let d_wqkv = kernels::gemm(&n1, true, &d_qkv, false);
        let d_n1 = kernels::gemm(&d_qkv, false, &layer.wqkv, true);
        let (d_x1, d_gamma_attn) = rmsnorm_bwd(&lc.x_resid, &lc.r1, &layer.gamma_attn, &d_n1);

        // x feeds both the RMSNorm and the residual: accumulate both paths.
        let mut d_x_layer = d_x1;
        for i in 0..d_x_layer.data.len() {
            d_x_layer.data[i] += d_h.data[i];
        }
        d_x = d_x_layer;

        layer_grads.push(LayerGrad { d_gamma_attn, d_wqkv, d_wo, d_gamma_ffn, d_wgu, d_wdown });
    }
    layer_grads.reverse();

    // --- Embedding: scatter the input gradient back into the table. ---
    let mut d_embed = Mat::zeros(cfg.vocab, cfg.d_model);
    for (i, &tok) in cache.tokens.iter().enumerate() {
        for j in 0..cfg.d_model {
            d_embed.add(tok, j, d_x.get(i, j));
        }
    }

    (loss, Grads { d_embed, layers: layer_grads, d_gamma_final, d_lm_head })
}

/// `rmsnorm(x) ⊙ γ` reconstructed from `x`, its cached factor `r`, and `γ`.
fn col_scale_rms(x: &Mat, r: &[f32], gamma: &[f32]) -> Mat {
    let mut nrm = Mat::zeros(x.rows, x.cols);
    for i in 0..x.rows {
        for j in 0..x.cols {
            nrm.set(i, j, x.get(i, j) * r[i]);
        }
    }
    col_scale(&nrm, gamma)
}

// ---------------------------------------------------------------------------
// Adam optimizer + training loop.
// ---------------------------------------------------------------------------

/// Adam optimizer state, one moment pair per parameter group.
pub struct Adam {
    m: Vec<Vec<f32>>,
    v: Vec<Vec<f32>>,
    t: i32,
    lr: f32,
    b1: f32,
    b2: f32,
    eps: f32,
}

impl Adam {
    /// Allocate optimizer state matching the model's parameters.
    pub fn new(model: &mut Model, lr: f32) -> Adam {
        let sizes: Vec<usize> = model.params_mut().iter().map(|p| p.len()).collect();
        Adam {
            m: sizes.iter().map(|&n| vec![0.0; n]).collect(),
            v: sizes.iter().map(|&n| vec![0.0; n]).collect(),
            t: 0,
            lr,
            b1: 0.9,
            b2: 0.999,
            eps: 1e-8,
        }
    }

    /// One Adam update step.
    pub fn step(&mut self, model: &mut Model, grads: &Grads) {
        self.t += 1;
        let bc1 = 1.0 - self.b1.powi(self.t);
        let bc2 = 1.0 - self.b2.powi(self.t);
        let mut params = model.params_mut();
        let gflat = grads.flat();
        assert_eq!(params.len(), gflat.len(), "param/grad group count mismatch");
        for gi in 0..params.len() {
            let p = &mut params[gi];
            let g = gflat[gi];
            let m = &mut self.m[gi];
            let v = &mut self.v[gi];
            for i in 0..p.len() {
                m[i] = self.b1 * m[i] + (1.0 - self.b1) * g[i];
                v[i] = self.b2 * v[i] + (1.0 - self.b2) * g[i] * g[i];
                let mhat = m[i] / bc1;
                let vhat = v[i] / bc2;
                p[i] -= self.lr * mhat / (vhat.sqrt() + self.eps);
            }
        }
    }
}

/// Train the model to fit `(tokens -> targets)`; returns the loss every
/// `report` steps.
pub fn train(
    model: &mut Model,
    tokens: &[usize],
    targets: &[usize],
    steps: usize,
    lr: f32,
    report: usize,
) -> Vec<(usize, f32)> {
    let mut opt = Adam::new(model, lr);
    let mut curve = Vec::new();
    for step in 0..steps {
        let (_, cache) = model.forward(tokens);
        let (loss, grads) = backward(model, &cache, targets);
        opt.step(model, &grads);
        if step % report == 0 || step == steps - 1 {
            curve.push((step, loss));
        }
    }
    curve
}

/// Finite-difference gradient check via **directional derivatives**.
///
/// A per-parameter finite difference is numerically hopeless in f32: the loss
/// change for one weight sits at the f32 rounding floor. Instead we perturb
/// *all* parameters along a random direction `u`, so the loss change is the
/// sum of thousands of contributions and rises well above the noise floor.
/// The analytic directional derivative `∇L · u` is then compared against the
/// central difference `(L(θ + hu) - L(θ - hu)) / 2h`.
///
/// Returns the worst relative error over `n_dirs` random directions.
pub fn grad_check(
    model: &mut Model,
    tokens: &[usize],
    targets: &[usize],
    n_dirs: usize,
    seed: u64,
) -> f32 {
    let (_, cache) = model.forward(tokens);
    let (_, grads) = backward(model, &cache, targets);
    let gflat: Vec<Vec<f32>> = grads.flat().iter().map(|s| s.to_vec()).collect();
    let lens: Vec<usize> = model.params_mut().iter().map(|p| p.len()).collect();

    // The direction has +/-1 entries (L2 norm sqrt(N)); scaling `h` by
    // 1/sqrt(N) keeps the actual step in parameter space at a fixed ~1e-2,
    // small enough for an accurate central difference yet large enough that
    // the f32 loss change stays well clear of the rounding floor.
    let total: usize = lens.iter().sum();
    let h = 1e-2f32 / (total as f32).sqrt();
    let mut rng = crate::model::Rng::new(seed);
    let mut worst = 0.0f32;

    for _ in 0..n_dirs {
        // Random +/-1 direction over every parameter.
        let dir: Vec<Vec<f32>> = lens
            .iter()
            .map(|&n| (0..n).map(|_| if rng.uniform() < 0.5 { -1.0 } else { 1.0 }).collect())
            .collect();

        // Analytic directional derivative.
        let mut dot = 0.0f32;
        for g in 0..lens.len() {
            for i in 0..lens[g] {
                dot += gflat[g][i] * dir[g][i];
            }
        }

        // L(theta + h*u).
        {
            let mut p = model.params_mut();
            for g in 0..lens.len() {
                for i in 0..lens[g] {
                    p[g][i] += h * dir[g][i];
                }
            }
        }
        let lp = loss_of(model, tokens, targets);
        // L(theta - h*u).
        {
            let mut p = model.params_mut();
            for g in 0..lens.len() {
                for i in 0..lens[g] {
                    p[g][i] -= 2.0 * h * dir[g][i];
                }
            }
        }
        let lm = loss_of(model, tokens, targets);
        // Restore.
        {
            let mut p = model.params_mut();
            for g in 0..lens.len() {
                for i in 0..lens[g] {
                    p[g][i] += h * dir[g][i];
                }
            }
        }

        let numeric = (lp - lm) / (2.0 * h);
        let denom = numeric.abs().max(dot.abs()).max(1e-3);
        worst = worst.max((numeric - dot).abs() / denom);
    }
    worst
}
