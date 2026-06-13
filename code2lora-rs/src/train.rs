//! Pure-Rust gradient training of the Code2LoRA-Static hypernetwork (§3.4).
//!
//! Training the full ~720M hypernetwork that adapts Qwen needs a GPU (it must
//! backprop through the frozen base LLM). To *prove the architecture learns and
//! generalizes* without one, we train the identical Static hypernetwork shape
//! (trunk → per-module head, `A=tanh(·)·exp(sᴬ)`, `ΔW=(α/r)BA`) on a tractable
//! frozen-base adaptation task with full hand-written backprop:
//!
//!   * a frozen base matrix `W0`;
//!   * a *fixed ground-truth* linear hypernetwork that maps each repository
//!     embedding `e_r` to a low-rank target adaptation `ΔT_r` of `W0`;
//!   * our MLP hypernetwork must learn `e_r ↦ ΔW(e_r) ≈ ΔT_r` from
//!     input/output behavior, then **generalize to unseen repositories**.
//!
//! Success criterion: on held-out repos the trained hypernetwork drives the
//! adaptation error far below both the no-adaptation baseline and the untrained
//! initialization — i.e. it learned to synthesize repo-specific adapters.

use crate::tensor::{gelu, Rng};

#[derive(Clone)]
pub struct TrainConfig {
    pub demb: usize,      // repository embedding dim (paper: 2048)
    pub din: usize,       // base layer input dim
    pub dout: usize,      // base layer output dim
    pub trunk_h: usize,   // trunk hidden H
    pub d_h: usize,       // head input dim d_h
    pub rank: usize,      // LoRA rank of our hypernetwork
    pub true_rank: usize, // rank of the ground-truth adaptation
    pub alpha: f32,
    pub n_train: usize,
    pub n_test: usize,
    pub x_per_repo: usize,
    pub steps: usize,
    pub lr: f32,
    pub weight_decay: f32,
    pub log_scale_init: f32,
    pub seed: u64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        TrainConfig {
            demb: 32,
            din: 6,
            dout: 6,
            trunk_h: 48,
            d_h: 48,
            rank: 4,
            true_rank: 2,
            alpha: 4.0,
            n_train: 600,
            n_test: 100,
            x_per_repo: 24,
            steps: 3000,
            lr: 5e-3,
            weight_decay: 2e-4,
            log_scale_init: -1.5,
            seed: 0,
        }
    }
}

#[derive(Debug)]
pub struct TrainReport {
    pub baseline_loss: f32, // no adaptation (ΔW = 0)
    pub init_loss: f32,     // untrained hypernetwork, held-out
    pub trained_loss: f32,  // trained hypernetwork, held-out
    pub curve: Vec<f32>,    // training loss snapshots
}

/// A repository: its embedding and ground-truth low-rank adaptation of W0.
struct Repo {
    e: Vec<f32>,
    dt: Vec<f32>, // ΔT_r flattened [dout*din]
    xs: Vec<Vec<f32>>,
    ys: Vec<Vec<f32>>, // (W0+ΔT_r) x
}

fn matvec(w: &[f32], rows: usize, cols: usize, x: &[f32]) -> Vec<f32> {
    let mut y = vec![0.0f32; rows];
    for r in 0..rows {
        let base = r * cols;
        let mut acc = 0.0;
        for c in 0..cols {
            acc += w[base + c] * x[c];
        }
        y[r] = acc;
    }
    y
}

/// Trainable parameters of the small dense Static hypernetwork.
struct Params {
    w1: Vec<f32>, // [trunk_h, demb]
    b1: Vec<f32>, // [trunk_h]
    w2: Vec<f32>, // [d_h, trunk_h]
    b2: Vec<f32>, // [d_h]
    wa: Vec<f32>, // [rank*din, d_h]
    wb: Vec<f32>, // [dout*rank, d_h]
    sa: f32,
    sb: f32,
}

struct Grads {
    w1: Vec<f32>,
    b1: Vec<f32>,
    w2: Vec<f32>,
    b2: Vec<f32>,
    wa: Vec<f32>,
    wb: Vec<f32>,
    sa: f32,
    sb: f32,
}

impl Grads {
    fn zeros(c: &TrainConfig) -> Self {
        Grads {
            w1: vec![0.0; c.trunk_h * c.demb],
            b1: vec![0.0; c.trunk_h],
            w2: vec![0.0; c.d_h * c.trunk_h],
            b2: vec![0.0; c.d_h],
            wa: vec![0.0; c.rank * c.din * c.d_h],
            wb: vec![0.0; c.dout * c.rank * c.d_h],
            sa: 0.0,
            sb: 0.0,
        }
    }
}

fn gelu_grad(x: f32) -> f32 {
    let c = 0.7978845608028654;
    let u = c * (x + 0.044715 * x * x * x);
    let t = u.tanh();
    let du = c * (1.0 + 3.0 * 0.044715 * x * x);
    0.5 * (1.0 + t) + 0.5 * x * (1.0 - t * t) * du
}

struct Cache {
    g1: Vec<f32>,
    a1: Vec<f32>,
    m: Vec<f32>,
    nrm: f32,
    h: Vec<f32>,
    pa: Vec<f32>,
    pb: Vec<f32>,
    a: Vec<f32>, // [rank, din]
    b: Vec<f32>, // [dout, rank]
    dw: Vec<f32>,
}

impl Params {
    fn new(c: &TrainConfig, rng: &mut Rng) -> Self {
        let mk = |rows: usize, cols: usize, rng: &mut Rng| {
            let s = 1.0 / (cols as f32).sqrt();
            (0..rows * cols).map(|_| rng.normal() * s).collect::<Vec<_>>()
        };
        Params {
            w1: mk(c.trunk_h, c.demb, rng),
            b1: vec![0.0; c.trunk_h],
            w2: mk(c.d_h, c.trunk_h, rng),
            b2: vec![0.0; c.d_h],
            wa: mk(c.rank * c.din, c.d_h, rng),
            wb: mk(c.dout * c.rank, c.d_h, rng),
            sa: c.log_scale_init,
            sb: c.log_scale_init,
        }
    }

    /// Forward: e -> ΔW [dout*din], caching intermediates for backprop.
    fn forward(&self, c: &TrainConfig, e: &[f32]) -> Cache {
        let mut g1 = matvec(&self.w1, c.trunk_h, c.demb, e);
        for i in 0..c.trunk_h {
            g1[i] += self.b1[i];
        }
        let a1: Vec<f32> = g1.iter().map(|&v| gelu(v)).collect();
        let mut m = matvec(&self.w2, c.d_h, c.trunk_h, &a1);
        for i in 0..c.d_h {
            m[i] += self.b2[i];
        }
        let nrm = (m.iter().map(|v| v * v).sum::<f32>()).sqrt().max(1e-12);
        let scale = (c.d_h as f32).sqrt();
        let h: Vec<f32> = m.iter().map(|&v| scale * v / nrm).collect();

        let pa = matvec(&self.wa, c.rank * c.din, c.d_h, &h);
        let pb = matvec(&self.wb, c.dout * c.rank, c.d_h, &h);
        let ea = self.sa.exp();
        let eb = self.sb.exp();
        let a: Vec<f32> = pa.iter().map(|&v| v.tanh() * ea).collect();
        let b: Vec<f32> = pb.iter().map(|&v| v.tanh() * eb).collect();

        // ΔW = (α/r) B A ; B[dout,rank], A[rank,din]
        let scale_lora = c.alpha / c.rank as f32;
        let mut dw = vec![0.0f32; c.dout * c.din];
        for o in 0..c.dout {
            for i in 0..c.din {
                let mut acc = 0.0;
                for k in 0..c.rank {
                    acc += b[o * c.rank + k] * a[k * c.din + i];
                }
                dw[o * c.din + i] = scale_lora * acc;
            }
        }
        Cache {
            g1,
            a1,
            m,
            nrm,
            h,
            pa,
            pb,
            a,
            b,
            dw,
        }
    }
}

/// Mean squared adaptation error over a repo set, given a ΔW provider.
fn eval_loss(c: &TrainConfig, repos: &[Repo], w0: &[f32], dw_of: impl Fn(&[f32]) -> Vec<f32>) -> f32 {
    let mut total = 0.0;
    let mut count = 0;
    for r in repos {
        let dw = dw_of(&r.e);
        for (x, y) in r.xs.iter().zip(r.ys.iter()) {
            let mut acc = 0.0;
            for o in 0..c.dout {
                let mut p = 0.0;
                for i in 0..c.din {
                    p += (w0[o * c.din + i] + dw[o * c.din + i]) * x[i];
                }
                let d = p - y[o];
                acc += d * d;
            }
            total += acc;
            count += 1;
        }
    }
    total / count as f32
}

fn make_repos(c: &TrainConfig, w0: &[f32], pa: &[f32], pb: &[f32], n: usize, rng: &mut Rng) -> Vec<Repo> {
    let scale_lora = c.alpha / c.true_rank as f32;
    (0..n)
        .map(|_| {
            let e: Vec<f32> = (0..c.demb).map(|_| rng.normal()).collect();
            // ground-truth low-rank adaptation from a fixed linear hypernetwork
            let ta = matvec(pa, c.true_rank * c.din, c.demb, &e);
            let tb = matvec(pb, c.dout * c.true_rank, c.demb, &e);
            let mut dt = vec![0.0f32; c.dout * c.din];
            for o in 0..c.dout {
                for i in 0..c.din {
                    let mut acc = 0.0;
                    for k in 0..c.true_rank {
                        acc += tb[o * c.true_rank + k] * ta[k * c.din + i];
                    }
                    dt[o * c.din + i] = scale_lora * acc;
                }
            }
            let mut xs = Vec::with_capacity(c.x_per_repo);
            let mut ys = Vec::with_capacity(c.x_per_repo);
            for _ in 0..c.x_per_repo {
                let x: Vec<f32> = (0..c.din).map(|_| rng.normal()).collect();
                let mut y = vec![0.0f32; c.dout];
                for o in 0..c.dout {
                    let mut p = 0.0;
                    for i in 0..c.din {
                        p += (w0[o * c.din + i] + dt[o * c.din + i]) * x[i];
                    }
                    y[o] = p;
                }
                xs.push(x);
                ys.push(y);
            }
            Repo { e, dt, xs, ys }
        })
        .collect()
}

/// Accumulate gradients for one repo into `g`; returns the repo's loss.
fn backward_repo(c: &TrainConfig, p: &Params, w0: &[f32], r: &Repo, g: &mut Grads) -> f32 {
    let cache = p.forward(c, &r.e);
    let scale_lora = c.alpha / c.rank as f32;

    // dL/dΔW summed over x ; loss
    let mut gdw = vec![0.0f32; c.dout * c.din];
    let mut loss = 0.0;
    for (x, y) in r.xs.iter().zip(r.ys.iter()) {
        let mut pred = vec![0.0f32; c.dout];
        for o in 0..c.dout {
            let mut acc = 0.0;
            for i in 0..c.din {
                acc += (w0[o * c.din + i] + cache.dw[o * c.din + i]) * x[i];
            }
            pred[o] = acc;
        }
        for o in 0..c.dout {
            let resid = pred[o] - y[o];
            loss += resid * resid;
            let gd = 2.0 * resid;
            for i in 0..c.din {
                gdw[o * c.din + i] += gd * x[i];
            }
        }
    }

    // through ΔW = scale_lora * B A
    // dL/dA = scale_lora * Bᵀ gdw ; dL/dB = scale_lora * gdw Aᵀ
    let mut ga = vec![0.0f32; c.rank * c.din];
    let mut gb = vec![0.0f32; c.dout * c.rank];
    for k in 0..c.rank {
        for i in 0..c.din {
            let mut acc = 0.0;
            for o in 0..c.dout {
                acc += cache.b[o * c.rank + k] * gdw[o * c.din + i];
            }
            ga[k * c.din + i] = scale_lora * acc;
        }
    }
    for o in 0..c.dout {
        for k in 0..c.rank {
            let mut acc = 0.0;
            for i in 0..c.din {
                acc += gdw[o * c.din + i] * cache.a[k * c.din + i];
            }
            gb[o * c.rank + k] = scale_lora * acc;
        }
    }

    // through tanh·exp scaling
    let ea = p.sa.exp();
    let eb = p.sb.exp();
    let mut gpa = vec![0.0f32; c.rank * c.din];
    let mut gpb = vec![0.0f32; c.dout * c.rank];
    for idx in 0..ga.len() {
        let t = cache.pa[idx].tanh();
        gpa[idx] = ga[idx] * (1.0 - t * t) * ea;
        g.sa += ga[idx] * cache.a[idx]; // dL/dsa = Σ gA * A
    }
    for idx in 0..gb.len() {
        let t = cache.pb[idx].tanh();
        gpb[idx] = gb[idx] * (1.0 - t * t) * eb;
        g.sb += gb[idx] * cache.b[idx];
    }

    // heads: dL/dWA = gpa ⊗ h ; dL/dh += WAᵀ gpa  (same for B)
    let mut gh = vec![0.0f32; c.d_h];
    for row in 0..c.rank * c.din {
        let gp = gpa[row];
        let wbase = row * c.d_h;
        for j in 0..c.d_h {
            g.wa[wbase + j] += gp * cache.h[j];
            gh[j] += p.wa[wbase + j] * gp;
        }
    }
    for row in 0..c.dout * c.rank {
        let gp = gpb[row];
        let wbase = row * c.d_h;
        for j in 0..c.d_h {
            g.wb[wbase + j] += gp * cache.h[j];
            gh[j] += p.wb[wbase + j] * gp;
        }
    }

    // h = scale * m / nrm   (L2 normalize then scale)
    let scale = (c.d_h as f32).sqrt();
    let mut gmhat = vec![0.0f32; c.d_h];
    for j in 0..c.d_h {
        gmhat[j] = scale * gh[j];
    }
    let mhat: Vec<f32> = cache.m.iter().map(|&v| v / cache.nrm).collect();
    let dot: f32 = mhat.iter().zip(gmhat.iter()).map(|(a, b)| a * b).sum();
    let mut gm = vec![0.0f32; c.d_h];
    for j in 0..c.d_h {
        gm[j] = (gmhat[j] - mhat[j] * dot) / cache.nrm;
    }

    // m = W2 a1 + b2
    let mut ga1 = vec![0.0f32; c.trunk_h];
    for o in 0..c.d_h {
        let gmo = gm[o];
        g.b2[o] += gmo;
        let wbase = o * c.trunk_h;
        for i in 0..c.trunk_h {
            g.w2[wbase + i] += gmo * cache.a1[i];
            ga1[i] += p.w2[wbase + i] * gmo;
        }
    }

    // a1 = gelu(g1)
    let mut gg1 = vec![0.0f32; c.trunk_h];
    for i in 0..c.trunk_h {
        gg1[i] = ga1[i] * gelu_grad(cache.g1[i]);
    }

    // g1 = W1 e + b1
    for o in 0..c.trunk_h {
        let ggo = gg1[o];
        g.b1[o] += ggo;
        let wbase = o * c.demb;
        for i in 0..c.demb {
            g.w1[wbase + i] += ggo * r.e[i];
        }
    }

    loss / r.xs.len() as f32
}

/// Adam optimizer state for the parameter vectors.
struct Adam {
    m: Vec<f32>,
    v: Vec<f32>,
    t: f32,
}
impl Adam {
    fn new(n: usize) -> Self {
        Adam { m: vec![0.0; n], v: vec![0.0; n], t: 0.0 }
    }
    fn step(&mut self, w: &mut [f32], g: &[f32], lr: f32, wd: f32) {
        self.t += 1.0;
        let (b1, b2, eps) = (0.9f32, 0.999f32, 1e-8f32);
        let bc1 = 1.0 - b1.powf(self.t);
        let bc2 = 1.0 - b2.powf(self.t);
        for i in 0..w.len() {
            self.m[i] = b1 * self.m[i] + (1.0 - b1) * g[i];
            self.v[i] = b2 * self.v[i] + (1.0 - b2) * g[i] * g[i];
            let mh = self.m[i] / bc1;
            let vh = self.v[i] / bc2;
            w[i] -= lr * (mh / (vh.sqrt() + eps) + wd * w[i]); // decoupled weight decay
        }
    }
}

pub fn run_demo(c: &TrainConfig) -> TrainReport {
    let mut rng = Rng::new(c.seed);
    let w0: Vec<f32> = (0..c.dout * c.din).map(|_| rng.normal() * 0.3).collect();
    // fixed ground-truth linear hypernetwork
    let pa_true: Vec<f32> = (0..c.true_rank * c.din * c.demb)
        .map(|_| rng.normal() / (c.demb as f32).sqrt())
        .collect();
    let pb_true: Vec<f32> = (0..c.dout * c.true_rank * c.demb)
        .map(|_| rng.normal() / (c.demb as f32).sqrt())
        .collect();

    let train = make_repos(c, &w0, &pa_true, &pb_true, c.n_train, &mut rng);
    let test = make_repos(c, &w0, &pa_true, &pb_true, c.n_test, &mut rng);

    let mut params = Params::new(c, &mut rng);

    let zero_dw = |_e: &[f32]| vec![0.0f32; c.dout * c.din];
    let baseline_loss = eval_loss(c, &test, &w0, zero_dw);
    let init_loss = eval_loss(c, &test, &w0, |e| params.forward(c, e).dw);

    // Adam states per parameter group
    let mut a_w1 = Adam::new(params.w1.len());
    let mut a_b1 = Adam::new(params.b1.len());
    let mut a_w2 = Adam::new(params.w2.len());
    let mut a_b2 = Adam::new(params.b2.len());
    let mut a_wa = Adam::new(params.wa.len());
    let mut a_wb = Adam::new(params.wb.len());
    let mut a_s = Adam::new(2);

    let mut curve = Vec::new();
    for step in 0..c.steps {
        let mut g = Grads::zeros(c);
        let mut loss = 0.0;
        for r in &train {
            loss += backward_repo(c, &params, &w0, r, &mut g);
        }
        let n = train.len() as f32;
        let scale = 1.0 / n;
        for x in g.w1.iter_mut() { *x *= scale; }
        for x in g.b1.iter_mut() { *x *= scale; }
        for x in g.w2.iter_mut() { *x *= scale; }
        for x in g.b2.iter_mut() { *x *= scale; }
        for x in g.wa.iter_mut() { *x *= scale; }
        for x in g.wb.iter_mut() { *x *= scale; }
        g.sa *= scale;
        g.sb *= scale;

        let wd = c.weight_decay;
        a_w1.step(&mut params.w1, &g.w1, c.lr, wd);
        a_b1.step(&mut params.b1, &g.b1, c.lr, 0.0);
        a_w2.step(&mut params.w2, &g.w2, c.lr, wd);
        a_b2.step(&mut params.b2, &g.b2, c.lr, 0.0);
        a_wa.step(&mut params.wa, &g.wa, c.lr, wd);
        a_wb.step(&mut params.wb, &g.wb, c.lr, wd);
        let mut s = [params.sa, params.sb];
        a_s.step(&mut s, &[g.sa, g.sb], c.lr, 0.0);
        params.sa = s[0];
        params.sb = s[1];

        if step % (c.steps / 20).max(1) == 0 {
            curve.push(loss / n);
        }
    }

    let trained_loss = eval_loss(c, &test, &w0, |e| params.forward(c, e).dw);
    // silence unused field warning while keeping the struct self-documenting
    let _ = &train[0].dt;
    TrainReport {
        baseline_loss,
        init_loss,
        trained_loss,
        curve,
    }
}
