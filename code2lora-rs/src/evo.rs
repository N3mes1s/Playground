//! Code2LoRA-Evo (paper §3.3): maintain a repository-specific adapter over a
//! chronological stream of commit diffs.
//!
//!   h0    = LayerNorm( GELU( Linear(e_repo^(0)) ) )          repo-state init
//!   x_t   = LayerNorm( Linear(e_t) )                         per-diff projection
//!   z_t   = GRU(x_t, z_{t-1})                                recurrent aggregation
//!   A_t,B_t = Head( LayerNorm(z_t) )                         shared Static head
//!
//! Each commit advances the GRU by one step on the stored diff embedding (cheap,
//! no full re-encode) and re-emits an adapter — yielding an *adapter trajectory*
//! over the repository's lifetime. The recurrence augments (not replaces) the
//! snapshot prior carried in `h0`.

use crate::embedder::EMBED_DIM;
use crate::hypernet::{HyperNet, HyperNetConfig, LoraAdapter};
use crate::model::ModelSpec;
use crate::tensor::{gelu, layernorm, sigmoid, Mat, Rng};

const EPS: f32 = 1e-5;

/// Repository-level embedding width (matches the Static encoder output).
pub const REPO_DIM: usize = 2 * EMBED_DIM; // 2048

/// Minimal GRU cell (PyTorch formulation), hidden == input dim.
struct GruCell {
    dim: usize,
    w_ir: Mat,
    w_iz: Mat,
    w_in: Mat,
    w_hr: Mat,
    w_hz: Mat,
    w_hn: Mat,
}

impl GruCell {
    fn new(dim: usize, rng: &mut Rng) -> Self {
        GruCell {
            dim,
            w_ir: Mat::randn(dim, dim, rng),
            w_iz: Mat::randn(dim, dim, rng),
            w_in: Mat::randn(dim, dim, rng),
            w_hr: Mat::randn(dim, dim, rng),
            w_hz: Mat::randn(dim, dim, rng),
            w_hn: Mat::randn(dim, dim, rng),
        }
    }

    fn step(&self, x: &[f32], h: &[f32]) -> Vec<f32> {
        let ir = self.w_ir.matvec(x);
        let hr = self.w_hr.matvec(h);
        let iz = self.w_iz.matvec(x);
        let hz = self.w_hz.matvec(h);
        let inn = self.w_in.matvec(x);
        let hn = self.w_hn.matvec(h);
        let mut out = vec![0.0f32; self.dim];
        for i in 0..self.dim {
            let r = sigmoid(ir[i] + hr[i]);
            let z = sigmoid(iz[i] + hz[i]);
            let n = (inn[i] + r * hn[i]).tanh();
            out[i] = (1.0 - z) * n + z * h[i];
        }
        out
    }
}

pub struct EvoHyperNet {
    in_proj: Mat,   // Linear(REPO_DIM -> REPO_DIM) for diff embeddings
    init_proj: Mat, // Linear(REPO_DIM -> REPO_DIM) for the snapshot prior
    gru: GruCell,
    head: HyperNet, // shared Static head, consumes LayerNorm(z_t) of size REPO_DIM
}

impl EvoHyperNet {
    pub fn new(spec: ModelSpec, seed: u64) -> Self {
        let mut rng = Rng::new(seed ^ 0xE0_0E_5A_FE);
        let in_proj = Mat::randn(REPO_DIM, REPO_DIM, &mut rng);
        let init_proj = Mat::randn(REPO_DIM, REPO_DIM, &mut rng);
        let gru = GruCell::new(REPO_DIM, &mut rng);
        // Evo head: trunk hidden 1024 (paper), input dim = REPO_DIM.
        let head_cfg = HyperNetConfig {
            trunk_hidden: 1024,
            seed,
            ..Default::default()
        };
        let head = HyperNet::new(spec, head_cfg, REPO_DIM);
        EvoHyperNet {
            in_proj,
            init_proj,
            gru,
            head,
        }
    }

    /// Initial GRU state from the first repository snapshot embedding.
    pub fn init_state(&self, e0: &[f32]) -> Vec<f32> {
        let mut h = self.init_proj.matvec(e0);
        for v in h.iter_mut() {
            *v = gelu(*v);
        }
        layernorm(&mut h, EPS);
        h
    }

    /// Advance one commit: z_t = GRU(LayerNorm(Linear(e_t)), z_{t-1}).
    pub fn step(&self, z_prev: &[f32], e_t: &[f32]) -> Vec<f32> {
        let mut x = self.in_proj.matvec(e_t);
        layernorm(&mut x, EPS);
        self.gru.step(&x, z_prev)
    }

    /// Emit the adapter for the current state.
    pub fn adapter_from_state(&self, z: &[f32]) -> LoraAdapter {
        let mut zn = z.to_vec();
        layernorm(&mut zn, EPS);
        self.head.generate(&zn)
    }

    /// Walk a chronological stream of diff embeddings, returning the adapter
    /// trajectory (one adapter per commit), plus the final state.
    pub fn run(&self, e0: &[f32], diffs: &[Vec<f32>]) -> (Vec<LoraAdapter>, Vec<f32>) {
        let mut z = self.init_state(e0);
        let mut traj = Vec::with_capacity(diffs.len());
        for et in diffs {
            z = self.step(&z, et);
            traj.push(self.adapter_from_state(&z));
        }
        (traj, z)
    }
}
