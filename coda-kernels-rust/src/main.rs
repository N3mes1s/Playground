//! CODA-rs demonstration binary.
//!
//! Runs, in order: a correctness check of all 10 GEMM-plus-epilogue kernels;
//! a numerical-equivalence check of the fused vs. unfused Transformer forward
//! pass; a DRAM-traffic comparison that quantifies the fusion win; a
//! finite-difference gradient check of the backward pass; and finally a small
//! training run that memorizes a sentence and reproduces it by generation.

use coda::kernels;
use coda::model::{rms_factor, Config, Model, Rng};
use coda::reference as rf;
use coda::tensor::{self, Mat};
use coda::train;

/// A random matrix, for kernel correctness tests.
fn randmat(rng: &mut Rng, r: usize, c: usize, scale: f32) -> Mat {
    let mut m = Mat::zeros(r, c);
    for v in m.data.iter_mut() {
        *v = rng.normal() * scale;
    }
    m
}

/// `n x n` identity (used to feed a precomputed gradient through a GEMM).
fn identity(n: usize) -> Mat {
    let mut m = Mat::zeros(n, n);
    for i in 0..n {
        m.set(i, i, 1.0);
    }
    m
}

/// Print a PASS/FAIL line for a tolerance check.
fn check(name: &str, diff: f32, tol: f32) -> bool {
    let ok = diff <= tol && diff.is_finite();
    println!(
        "    [{}] {:<44} max-err = {:.3e}  (tol {:.0e})",
        if ok { "PASS" } else { "FAIL" },
        name,
        diff,
        tol
    );
    ok
}

fn rule(title: &str) {
    println!("\n{}", "=".repeat(72));
    println!("  {title}");
    println!("{}", "=".repeat(72));
}

fn main() {
    println!("CODA-rs : Transformer blocks as GEMM-plus-epilogue programs");
    println!("a CPU/Rust port of Guo et al., arXiv:2605.19269");

    let mut rng = Rng::new(0xC0DA);
    let mut all_ok = true;

    // -------------------------------------------------------------------
    rule("1. Kernel correctness : all 10 GEMM-plus-epilogue kernels");
    // -------------------------------------------------------------------
    {
        let tol = 2e-3;
        let (m, k, n) = (40, 48, 64);
        let a = randmat(&mut rng, m, k, 0.5);
        let b = randmat(&mut rng, k, n, 0.5);
        let c = randmat(&mut rng, m, n, 0.5);
        let gamma: Vec<f32> = (0..n).map(|_| 0.8 + 0.4 * rng.uniform()).collect();
        let eps = 1e-5;

        // RoPE tables for an m-row, n-col problem (pair every 16 dims).
        let mut cos = Mat::zeros(m, n);
        let mut sin = Mat::zeros(m, n);
        for i in 0..m {
            for p in 0..n / 2 {
                let ang = i as f32 * 10000f32.powf(-2.0 * (p % 8) as f32 / 16.0);
                cos.set(i, 2 * p, ang.cos());
                cos.set(i, 2 * p + 1, ang.cos());
                sin.set(i, 2 * p, ang.sin());
                sin.set(i, 2 * p + 1, ang.sin());
            }
        }

        // Kernel 1: GEMM + RoPE.
        let k1 = kernels::gemm_rope(&a, &b, &cos, &sin);
        let k1_ref = rf::rope(&rf::gemm(&a, false, &b, false), &cos, &sin);
        all_ok &= check("Kernel 1  gemm_rope", k1.max_abs_diff(&k1_ref), tol);

        // Kernel 2: GEMM + SwiGLU.
        let k2 = kernels::gemm_swiglu(&a, &b);
        let k2_ref = rf::swiglu(&rf::gemm(&a, false, &b, false));
        all_ok &= check("Kernel 2  gemm_swiglu", k2.max_abs_diff(&k2_ref), tol);

        // Kernel 3: GEMM + partial cross-entropy.
        let targets: Vec<usize> = (0..m).map(|i| (i * 7 + 3) % n).collect();
        let (_, _, k3_loss) = kernels::gemm_partial_ce(&a, &b, &targets);
        let k3_ref = rf::cross_entropy(&rf::gemm(&a, false, &b, false), &targets);
        let k3_diff = k3_loss
            .iter()
            .zip(&k3_ref)
            .map(|(x, y)| (x - y).abs())
            .fold(0.0, f32::max);
        all_ok &= check("Kernel 3  gemm_partial_ce", k3_diff, tol);

        // Kernel 4: GEMM + residual + partial RMSNorm + weight scale.
        let (k4_d, k4_o, k4_r) = kernels::gemm_residual_partial_rms(&a, &b, &c, &gamma, eps);
        let d_ref = rf::residual(&rf::gemm(&a, false, &b, false), &c);
        let r_ref = rms_factor(&d_ref, eps);
        let o_ref = {
            let mut o = Mat::zeros(m, n);
            for i in 0..m {
                for j in 0..n {
                    o.set(i, j, d_ref.get(i, j) * gamma[j]);
                }
            }
            o
        };
        all_ok &= check("Kernel 4  gemm_residual_partial_rms (D)", k4_d.max_abs_diff(&d_ref), tol);
        all_ok &= check("Kernel 4  gemm_residual_partial_rms (O)", k4_o.max_abs_diff(&o_ref), tol);
        let r_diff = k4_r.iter().zip(&r_ref).map(|(x, y)| (x - y).abs()).fold(0.0, f32::max);
        all_ok &= check("Kernel 4  gemm_residual_partial_rms (r)", r_diff, tol);

        // Kernel 5: GEMM + RMSNorm scaling.
        let r_vec: Vec<f32> = (0..m).map(|_| 0.5 + rng.uniform()).collect();
        let k5 = kernels::gemm_rmsnorm(&a, &b, &r_vec);
        let k5_ref = rf::row_scale(&rf::gemm(&a, false, &b, false), &r_vec);
        all_ok &= check("Kernel 5  gemm_rmsnorm", k5.max_abs_diff(&k5_ref), tol);

        // Kernel 6: GEMM + RMSNorm + SwiGLU (+ saved pre-activation D').
        let dprime = rf::row_scale(&rf::gemm(&a, false, &b, false), &r_vec);
        let (k6, k6_gu) = kernels::gemm_rmsnorm_swiglu(&a, &b, &r_vec);
        all_ok &= check("Kernel 6  gemm_rmsnorm_swiglu", k6.max_abs_diff(&rf::swiglu(&dprime)), tol);
        all_ok &= check("Kernel 6  gemm_rmsnorm_swiglu (saved D')", k6_gu.max_abs_diff(&dprime), tol);

        // Kernel 7: GEMM + RMSNorm + RoPE.
        let k7 = kernels::gemm_rmsnorm_rope(&a, &b, &r_vec, &cos, &sin);
        let k7_ref = rf::rope(&rf::row_scale(&rf::gemm(&a, false, &b, false), &r_vec), &cos, &sin);
        all_ok &= check("Kernel 7  gemm_rmsnorm_rope", k7.max_abs_diff(&k7_ref), tol);

        // Kernel 8: GEMM + RMSNorm + partial cross-entropy.
        let (_, _, k8_loss) = kernels::gemm_rmsnorm_partial_ce(&a, &b, &r_vec, &targets);
        let k8_ref = rf::cross_entropy(&rf::row_scale(&rf::gemm(&a, false, &b, false), &r_vec), &targets);
        let k8_diff = k8_loss.iter().zip(&k8_ref).map(|(x, y)| (x - y).abs()).fold(0.0, f32::max);
        all_ok &= check("Kernel 8  gemm_rmsnorm_partial_ce", k8_diff, tol);

        // Kernel 9: GEMM + residual + RMSNorm backward (finite-difference).
        all_ok &= check("Kernel 9  gemm_residual_rmsnorm_bwd", kernel9_fd_error(&mut rng), 3e-2);

        // Kernel 10: GEMM + SwiGLU backward (finite-difference).
        all_ok &= check("Kernel 10 gemm_swiglu_bwd", kernel10_fd_error(&mut rng), 3e-2);
    }

    // -------------------------------------------------------------------
    rule("2. Fused vs. unfused Transformer forward : numerical equivalence");
    // -------------------------------------------------------------------
    let (corpus, vocab_chars, tokens) = build_corpus();
    let cfg = Config::tiny(vocab_chars.len());
    println!(
        "    model: d_model={}, layers={}, heads={}, d_ff={}, vocab={}",
        cfg.d_model, cfg.n_layers, cfg.n_heads, cfg.d_ff, cfg.vocab
    );
    let mut init_rng = Rng::new(42);
    let model = Model::new(cfg.clone(), &mut init_rng);
    let seq_in = &tokens[..tokens.len() - 1];
    let targets: Vec<usize> = tokens[1..].to_vec();

    let (logits_coda, _) = model.forward(seq_in);
    let logits_ref = model.forward_ref(seq_in);
    let fwd_diff = logits_coda.max_abs_diff(&logits_ref);
    all_ok &= check("CODA forward == naive operator-sequence forward", fwd_diff, 5e-3);

    // -------------------------------------------------------------------
    rule("3. DRAM traffic : what the epilogue fusion saves");
    // -------------------------------------------------------------------
    {
        // The fusion removes activation-sized round-trips; its relative weight
        // grows with the sequence length (the paper benchmarks 16K tokens).
        println!("    forward-pass bytes through global memory, fused vs. unfused:");
        let mut all_lt = true;
        for &t_meas in &[seq_in.len(), 384, 2048] {
            let seq: Vec<usize> = (0..t_meas).map(|i| i % cfg.vocab).collect();
            tensor::reset_traffic();
            let _ = model.forward(&seq);
            let coda = tensor::traffic_bytes();
            tensor::reset_traffic();
            let _ = model.forward_ref(&seq);
            let refb = tensor::traffic_bytes();
            let saved = 100.0 * (1.0 - coda as f64 / refb as f64);
            all_lt &= coda < refb;
            println!(
                "      seq {:>5} : naive {:>8} KiB  |  CODA {:>8} KiB  |  saved {:>4.1}%",
                t_meas,
                refb / 1024,
                coda / 1024,
                saved
            );
        }
        println!("    the fused kernels never materialize the residual stream or the");
        println!("    normalized activations as standalone tensors.");
        all_ok &= all_lt;
        if !all_lt {
            println!("    [FAIL] expected the fused path to move less data");
        }
    }

    // -------------------------------------------------------------------
    rule("4. Backward pass : finite-difference gradient check");
    // -------------------------------------------------------------------
    {
        let mut gc_model = Model::new(cfg.clone(), &mut Rng::new(7));
        let short = &seq_in[..16.min(seq_in.len())];
        let short_tgt = &targets[..short.len()];
        let worst = train::grad_check(&mut gc_model, short, short_tgt, 6, 0x5EED);
        all_ok &= check("analytic grad == numeric grad (6 directions)", worst, 3e-2);
    }

    // -------------------------------------------------------------------
    rule("5. Small CPU model : train to memorize, then generate");
    // -------------------------------------------------------------------
    {
        println!("    corpus : \"{corpus}\"");
        let mut tm = Model::new(cfg.clone(), &mut Rng::new(1234));
        let t0 = std::time::Instant::now();
        let curve = train::train(&mut tm, seq_in, &targets, 700, 3e-3, 100);
        let secs = t0.elapsed().as_secs_f32();
        println!("    training (700 Adam steps, {secs:.1}s):");
        for (step, loss) in &curve {
            let bar = "#".repeat((loss * 6.0).min(48.0) as usize);
            println!("      step {step:>4}  loss {loss:>7.4}  {bar}");
        }
        let final_loss = curve.last().map(|x| x.1).unwrap_or(99.0);

        // Greedy generation from a short prompt.
        let prompt_len = 6;
        let generated = tm.generate(&tokens[..prompt_len], tokens.len() - prompt_len);
        let decoded: String = generated.iter().map(|&t| vocab_chars[t]).collect();
        let prompt: String = tokens[..prompt_len].iter().map(|&t| vocab_chars[t]).collect();
        println!("    prompt    : \"{prompt}\"");
        println!("    generated : \"{decoded}\"");
        let matched = decoded == corpus;
        println!(
            "    --> generation {} the training corpus.",
            if matched { "exactly reproduces" } else { "does NOT match" }
        );
        all_ok &= check("final training loss is small", final_loss, 0.2);
        if !matched {
            all_ok = false;
            println!("    [FAIL] generated text does not match corpus");
        }
    }

    rule("Summary");
    if all_ok {
        println!("  ALL CHECKS PASSED.");
        println!("  CODA's GEMM-plus-epilogue reparameterization is implemented in full,");
        println!("  is numerically faithful, saves global-memory traffic, and trains a");
        println!("  working Transformer on CPU. Ready to scale up on a Modal.com GPU.");
    } else {
        println!("  SOME CHECKS FAILED - see above.");
        std::process::exit(1);
    }
}

/// Finite-difference error for Kernel 9 (residual + RMSNorm backward).
///
/// RMSNorm forward: `h2 = (h1 * r) ⊙ γ`. With a fixed upstream `dh2`, define
/// `L = Σ dh2 ⊙ h2`; then `∇h1 = dL/dh1`. Kernel 9 should reproduce that.
fn kernel9_fd_error(rng: &mut Rng) -> f32 {
    let (m, n) = (12, 16);
    let eps = 1e-5;
    let h1 = randmat(rng, m, n, 0.7);
    let dh2 = randmat(rng, m, n, 0.7);
    let gamma: Vec<f32> = (0..n).map(|_| 0.7 + 0.6 * rng.uniform()).collect();

    let rms = |x: &Mat| rms_factor(x, eps);
    let h2 = |x: &Mat, r: &[f32]| {
        let mut o = Mat::zeros(m, n);
        for i in 0..m {
            for j in 0..n {
                o.set(i, j, x.get(i, j) * r[i] * gamma[j]);
            }
        }
        o
    };
    let loss = |x: &Mat| {
        let r = rms(x);
        let o = h2(x, &r);
        let mut l = 0.0f32;
        for i in 0..m * n {
            l += dh2.data[i] * o.data[i];
        }
        l
    };

    // CODA Kernel 9: feed dh2 through a GEMM (dh2 @ Iᵀ = dh2).
    let r = rms(&h1);
    let h2v = h2(&h1, &r);
    let s: Vec<f32> = (0..m)
        .map(|i| {
            let mut acc = 0.0;
            for j in 0..n {
                acc += dh2.get(i, j) * h2v.get(i, j);
            }
            acc / n as f32
        })
        .collect();
    let (dh1, _) = kernels::gemm_residual_rmsnorm_bwd(&dh2, &identity(n), &h1, &r, &gamma, &s);

    // Finite-difference reference.
    let h = 2e-3;
    let mut worst = 0.0f32;
    for i in 0..m {
        for j in 0..n {
            let mut hp = h1.clone();
            hp.add(i, j, h);
            let mut hm = h1.clone();
            hm.add(i, j, -h);
            let num = (loss(&hp) - loss(&hm)) / (2.0 * h);
            let den = num.abs().max(dh1.get(i, j).abs()).max(1e-3);
            worst = worst.max((num - dh1.get(i, j)).abs() / den);
        }
    }
    worst
}

/// Finite-difference error for Kernel 10 (SwiGLU backward).
fn kernel10_fd_error(rng: &mut Rng) -> f32 {
    let (m, half) = (12, 8);
    let n = 2 * half;
    let gu = randmat(rng, m, n, 0.8);
    let d_o = randmat(rng, m, half, 0.8);

    let loss = |z: &Mat| {
        let o = rf::swiglu(z);
        let mut l = 0.0f32;
        for i in 0..m * half {
            l += d_o.data[i] * o.data[i];
        }
        l
    };

    // CODA Kernel 10: dO @ Iᵀ = dO, then the SwiGLU backward epilogue.
    let (dz, _) = kernels::gemm_swiglu_bwd(&d_o, &identity(half), &gu);

    let h = 2e-3;
    let mut worst = 0.0f32;
    for i in 0..m {
        for j in 0..n {
            let mut zp = gu.clone();
            zp.add(i, j, h);
            let mut zm = gu.clone();
            zm.add(i, j, -h);
            let num = (loss(&zp) - loss(&zm)) / (2.0 * h);
            let den = num.abs().max(dz.get(i, j).abs()).max(1e-3);
            worst = worst.max((num - dz.get(i, j)).abs() / den);
        }
    }
    worst
}

/// The training corpus: returns `(text, vocab, token-ids)`.
fn build_corpus() -> (String, Vec<char>, Vec<usize>) {
    let corpus = "coda fuses transformer epilogues into a gemm kernel.".to_string();
    let mut vocab: Vec<char> = corpus.chars().collect();
    vocab.sort_unstable();
    vocab.dedup();
    let tokens: Vec<usize> = corpus
        .chars()
        .map(|c| vocab.iter().position(|&v| v == c).unwrap())
        .collect();
    (corpus, vocab, tokens)
}

