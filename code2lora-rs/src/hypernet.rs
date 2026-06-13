//! Code2LoRA-Static hypernetwork (paper §3.2).
//!
//! Maps a repository embedding `e ∈ R^{2d}` to a full LoRA adapter in one
//! forward pass:
//!
//!   h     = sqrt(d_h) · L2Norm( MLP_2GELU(e) )            (trunk, d_h = 1024)
//!   A_m   = tanh( HeadA_m(h) ) · exp(s^A_m)               per module type m
//!   B_m   = tanh( HeadB_m(h) ) · exp(s^B_m)
//!
//! with one (A_m, B_m) pair per module type m ∈ {q,k,v,o,gate,up,down}, shared
//! across all transformer layers, injected as W' = W + (α/r)·B_m·A_m.
//!
//! The trunk is a small stored MLP. The per-module-type heads are enormous
//! (~675M params total at d_h=1024, r=16 — the bulk of the paper's "~720M
//! trainable parameters"), so instead of materializing them we *stream* each
//! head row deterministically from the seed. This represents the network at its
//! initialization (log-scale −3.5 ⇒ small, near-identity adapters, exactly the
//! paper's init); training the streamed parameters is the GPU-bound step the
//! companion Tinker harness stands in for.

use crate::model::{ModelSpec, ModuleType, MODULE_TYPES};
use crate::tensor::{gelu, l2_normalize, Mat, Rng};

/// One generated LoRA adapter: an (A, B) pair per module type.
pub struct LoraAdapter {
    pub rank: usize,
    pub alpha: f32,
    /// (module, A[r, in], B[out, r]) in MODULE_TYPES order.
    pub mats: Vec<(ModuleType, Mat, Mat)>,
}

pub struct HyperNetConfig {
    pub trunk_hidden: usize, // H, paper: 512 (Static)
    pub head_dim: usize,     // d_h, paper: 1024
    pub rank: usize,         // r, paper: 16
    pub alpha: f32,          // α, paper: 32
    pub log_scale_init: f32, // s init, paper: −3.5
    pub seed: u64,
}

impl Default for HyperNetConfig {
    fn default() -> Self {
        HyperNetConfig {
            trunk_hidden: 512,
            head_dim: 1024,
            rank: 16,
            alpha: 32.0,
            log_scale_init: -3.5,
            seed: 0,
        }
    }
}

pub struct HyperNet {
    cfg: HyperNetConfig,
    spec: ModelSpec,
    // Trunk: Linear(2d -> H) -> GELU -> Linear(H -> d_h)
    w1: Mat,
    b1: Vec<f32>,
    w2: Mat,
    b2: Vec<f32>,
}

impl HyperNet {
    pub fn new(spec: ModelSpec, cfg: HyperNetConfig, input_dim: usize) -> Self {
        let mut rng = Rng::new(cfg.seed ^ 0xC0DE_2_10_4A);
        let w1 = Mat::randn(cfg.trunk_hidden, input_dim, &mut rng);
        let b1 = vec![0.0; cfg.trunk_hidden];
        let w2 = Mat::randn(cfg.head_dim, cfg.trunk_hidden, &mut rng);
        let b2 = vec![0.0; cfg.head_dim];
        HyperNet {
            cfg,
            spec,
            w1,
            b1,
            w2,
            b2,
        }
    }

    /// Trunk forward: e -> h ∈ R^{d_h}.
    fn trunk(&self, e: &[f32]) -> Vec<f32> {
        let mut h0 = self.w1.matvec(e);
        for (i, x) in h0.iter_mut().enumerate() {
            *x = gelu(*x + self.b1[i]);
        }
        let mut m = self.w2.matvec(&h0);
        for (i, x) in m.iter_mut().enumerate() {
            *x += self.b2[i];
        }
        l2_normalize(&mut m);
        let scale = (self.cfg.head_dim as f32).sqrt();
        for x in m.iter_mut() {
            *x *= scale;
        }
        m
    }

    /// Stream one head: produce `out_features` values = Head(h), where each row
    /// of the (out_features × d_h) weight matrix is generated deterministically
    /// from (seed, head_id, row). Returns the raw pre-activation values.
    fn head_stream(&self, head_id: u64, out_features: usize, h: &[f32]) -> Vec<f32> {
        let d_h = self.cfg.head_dim;
        let scale = 1.0 / (d_h as f32).sqrt();
        let mut out = vec![0.0f32; out_features];
        let base = self
            .cfg
            .seed
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(head_id.wrapping_mul(0x100000001b3));
        for (row, o) in out.iter_mut().enumerate() {
            let mut rng = Rng::new(base ^ (row as u64).wrapping_mul(0xD1B54A32D192ED03));
            let mut acc = 0.0f32;
            for &hv in h.iter() {
                acc += (rng.normal() * scale) * hv;
            }
            *o = acc;
        }
        out
    }

    /// Generate the full adapter for a repository embedding `e`.
    pub fn generate(&self, e: &[f32]) -> LoraAdapter {
        let h = self.trunk(e);
        let r = self.cfg.rank;
        let scale = self.cfg.log_scale_init.exp();
        let mut mats = Vec::with_capacity(MODULE_TYPES.len());

        for (ti, &m) in MODULE_TYPES.iter().enumerate() {
            let (in_f, out_f) = self.spec.lora_dims(m);

            // HeadA_m -> [r, in_f]; HeadB_m -> [out_f, r].
            let head_a = self.head_stream((ti as u64) * 2, r * in_f, &h);
            let head_b = self.head_stream((ti as u64) * 2 + 1, out_f * r, &h);

            let mut a = Mat::zeros(r, in_f);
            for (idx, raw) in head_a.iter().enumerate() {
                a.data[idx] = raw.tanh() * scale;
            }
            let mut b = Mat::zeros(out_f, r);
            for (idx, raw) in head_b.iter().enumerate() {
                b.data[idx] = raw.tanh() * scale;
            }
            mats.push((m, a, b));
        }

        LoraAdapter {
            rank: r,
            alpha: self.cfg.alpha,
            mats,
        }
    }
}
