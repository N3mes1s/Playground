//! Integration tests for the CODA-rs port.
//!
//! These check, independently of the demo binary, that every fused kernel
//! matches its unfused reference, that the two Transformer forward paths
//! agree, that fusion reduces DRAM traffic, that the analytic gradients pass
//! a finite-difference check, and that the model can be trained.

use coda::kernels;
use coda::reference as rf;
use coda::tensor::{self, Mat};
use coda_llama::model::{rms_factor, Config, Model, Rng};
use coda_llama::train;

fn randmat(rng: &mut Rng, r: usize, c: usize, s: f32) -> Mat {
    let mut m = Mat::zeros(r, c);
    for v in m.data.iter_mut() {
        *v = rng.normal() * s;
    }
    m
}

#[test]
fn forward_kernels_match_reference() {
    let mut rng = Rng::new(1);
    let (m, k, n) = (48, 56, 64);
    let a = randmat(&mut rng, m, k, 0.5);
    let b = randmat(&mut rng, k, n, 0.5);
    let c = randmat(&mut rng, m, n, 0.5);
    let gamma: Vec<f32> = (0..n).map(|_| 0.7 + 0.5 * rng.uniform()).collect();
    let r: Vec<f32> = (0..m).map(|_| 0.4 + rng.uniform()).collect();
    let eps = 1e-5;

    // Kernel 2: SwiGLU.
    let k2 = kernels::gemm_swiglu(&a, &b);
    assert!(k2.max_abs_diff(&rf::swiglu(&rf::gemm(&a, false, &b, false))) < 2e-3);

    // Kernel 4: residual + partial RMSNorm + weight scale.
    let (d, o, rr) = kernels::gemm_residual_partial_rms(&a, &b, &c, &gamma, eps);
    let d_ref = rf::residual(&rf::gemm(&a, false, &b, false), &c);
    assert!(d.max_abs_diff(&d_ref) < 2e-3);
    let r_ref = rms_factor(&d_ref, eps);
    assert!(rr.iter().zip(&r_ref).all(|(x, y)| (x - y).abs() < 2e-3));
    for i in 0..m {
        for j in 0..n {
            assert!((o.get(i, j) - d_ref.get(i, j) * gamma[j]).abs() < 2e-3);
        }
    }

    // Kernel 5: RMSNorm scaling.
    let k5 = kernels::gemm_rmsnorm(&a, &b, &r);
    assert!(k5.max_abs_diff(&rf::row_scale(&rf::gemm(&a, false, &b, false), &r)) < 2e-3);

    // Kernel 6: RMSNorm + SwiGLU, with the saved pre-activation.
    let dprime = rf::row_scale(&rf::gemm(&a, false, &b, false), &r);
    let (k6, k6_gu) = kernels::gemm_rmsnorm_swiglu(&a, &b, &r);
    assert!(k6.max_abs_diff(&rf::swiglu(&dprime)) < 2e-3);
    assert!(k6_gu.max_abs_diff(&dprime) < 2e-3);
}

#[test]
fn cross_entropy_kernels_match_reference() {
    let mut rng = Rng::new(2);
    let (m, k, n) = (40, 48, 96);
    let a = randmat(&mut rng, m, k, 0.4);
    let b = randmat(&mut rng, k, n, 0.4);
    let r: Vec<f32> = (0..m).map(|_| 0.5 + rng.uniform()).collect();
    let targets: Vec<usize> = (0..m).map(|i| (i * 5 + 1) % n).collect();

    let (_, _, loss3) = kernels::gemm_partial_ce(&a, &b, &targets);
    let ref3 = rf::cross_entropy(&rf::gemm(&a, false, &b, false), &targets);
    assert!(loss3.iter().zip(&ref3).all(|(x, y)| (x - y).abs() < 2e-3));

    let (_, _, loss8) = kernels::gemm_rmsnorm_partial_ce(&a, &b, &r, &targets);
    let ref8 = rf::cross_entropy(&rf::row_scale(&rf::gemm(&a, false, &b, false), &r), &targets);
    assert!(loss8.iter().zip(&ref8).all(|(x, y)| (x - y).abs() < 2e-3));
}

#[test]
fn backward_kernels_are_consistent() {
    // Kernel 10: gemm_swiglu_bwd must agree with the standalone SwiGLU
    // backward rule used by training.
    let mut rng = Rng::new(3);
    let (m, half) = (24, 16);
    let gu = randmat(&mut rng, m, 2 * half, 0.6);
    let d_o = randmat(&mut rng, m, half, 0.6);
    let mut ident = Mat::zeros(half, half);
    for i in 0..half {
        ident.set(i, i, 1.0);
    }
    let (dz_kernel, _) = kernels::gemm_swiglu_bwd(&d_o, &ident, &gu);
    let dz_ref = train::swiglu_bwd(&gu, &d_o);
    assert!(dz_kernel.max_abs_diff(&dz_ref) < 1e-4);
}

#[test]
fn transformer_forward_paths_agree() {
    let cfg = Config::tiny(24);
    let model = Model::new(cfg, &mut Rng::new(11));
    let tokens: Vec<usize> = (0..40).map(|i| (i * 3 + 7) % 24).collect();
    let (coda, _) = model.forward(&tokens);
    let naive = model.forward_ref(&tokens);
    assert!(coda.max_abs_diff(&naive) < 5e-3, "forward paths diverge");
}

#[test]
fn fusion_reduces_dram_traffic() {
    let cfg = Config::tiny(24);
    let model = Model::new(cfg, &mut Rng::new(12));
    let tokens: Vec<usize> = (0..256).map(|i| i % 24).collect();

    tensor::reset_traffic();
    let _ = model.forward(&tokens);
    let coda = tensor::traffic_bytes();

    tensor::reset_traffic();
    let _ = model.forward_ref(&tokens);
    let naive = tensor::traffic_bytes();

    assert!(coda < naive, "fused path moved {coda} >= naive {naive}");
}

#[test]
fn gradients_pass_finite_difference_check() {
    let cfg = Config::tiny(20);
    let mut model = Model::new(cfg, &mut Rng::new(13));
    let tokens: Vec<usize> = (0..14).map(|i| (i * 7 + 2) % 20).collect();
    let targets: Vec<usize> = (0..14).map(|i| (i * 5 + 3) % 20).collect();
    let worst = train::grad_check(&mut model, &tokens, &targets, 8, 0xABCD);
    assert!(worst < 3e-2, "worst directional gradient error = {worst}");
}

#[test]
fn model_trains_and_loss_drops() {
    let cfg = Config::tiny(16);
    let mut model = Model::new(cfg, &mut Rng::new(14));
    let tokens: Vec<usize> = (0..30).map(|i| (i * 3 + 1) % 16).collect();
    let targets: Vec<usize> = tokens.iter().map(|&t| (t + 1) % 16).collect();

    let before = train::loss_of(&model, &tokens, &targets);
    let curve = train::train(&mut model, &tokens, &targets, 300, 3e-3, 150);
    let after = curve.last().unwrap().1;
    assert!(after < before * 0.5, "loss {before} -> {after} did not drop enough");
    assert!(after < 0.5, "final loss {after} too high");
}

#[test]
#[should_panic(expected = "outside")]
fn ce_kernel_rejects_out_of_range_target() {
    let mut rng = Rng::new(99);
    let a = randmat(&mut rng, 8, 12, 0.4);
    let b = randmat(&mut rng, 12, 16, 0.4);
    // The last target (999) is outside [0, vocab=16); the fused CE kernel
    // must reject it instead of silently returning a wrong loss.
    let targets = vec![0, 1, 2, 3, 4, 5, 6, 999];
    let _ = kernels::gemm_partial_ce(&a, &b, &targets);
}

#[test]
#[should_panic(expected = "even output width")]
fn rope_kernel_rejects_odd_width() {
    let mut rng = Rng::new(98);
    let a = randmat(&mut rng, 8, 12, 0.4);
    let b = randmat(&mut rng, 12, 15, 0.4); // odd output width
    let cos = Mat::zeros(8, 15);
    let sin = Mat::zeros(8, 15);
    let _ = kernels::gemm_rope(&a, &b, &cos, &sin);
}
