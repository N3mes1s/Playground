//! GPU verification + benchmark binary for the CUDA backend.
//!
//! Built with `--features cuda` and run on a GPU (see `modal/run_gpu.py`), it
//! checks every CUDA GEMM-plus-epilogue kernel against the CPU implementation
//! in [`coda::kernels`] for numerical agreement, then benchmarks the central
//! GEMM-Residual-RMSNorm kernel on the GPU against the CPU.

#[cfg(not(feature = "cuda"))]
fn main() {
    eprintln!("coda-gpu requires the CUDA backend: rebuild with `--features cuda`.");
    std::process::exit(1);
}

#[cfg(feature = "cuda")]
fn main() {
    use coda::cuda;
    use coda::kernels;
    use coda::model::Rng;
    use coda::tensor::Mat;
    use std::time::Instant;

    fn randmat(rng: &mut Rng, r: usize, c: usize, s: f32) -> Mat {
        let mut m = Mat::zeros(r, c);
        for v in m.data.iter_mut() {
            *v = rng.normal() * s;
        }
        m
    }
    fn maxdiff(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| (x - y).abs()).fold(0.0, f32::max)
    }
    fn line(name: &str, diff: f32, tol: f32) -> bool {
        let ok = diff <= tol && diff.is_finite();
        println!(
            "    [{}] {:<40} max-err = {:.3e}  (tol {:.0e})",
            if ok { "PASS" } else { "FAIL" },
            name,
            diff,
            tol
        );
        ok
    }

    println!("CODA-rs : CUDA backend verification + benchmark");
    let count = cuda::device_count();
    if count == 0 {
        eprintln!("no CUDA device visible - is this running on a GPU?");
        std::process::exit(1);
    }
    println!("  CUDA device: {} ({} visible)\n", cuda::device_name(), count);

    let mut rng = Rng::new(0x_C0DA_6E11);
    let mut ok = true;
    let tol = 1e-2;

    // ---- Kernel-by-kernel numerical agreement, GPU vs CPU ----
    println!("== Kernel correctness: CUDA vs CPU reference ==");
    let (m, k, n) = (96, 128, 64);
    let a = randmat(&mut rng, m, k, 0.4);
    let b = randmat(&mut rng, k, n, 0.4);
    let c = randmat(&mut rng, m, n, 0.4);
    let gamma: Vec<f32> = (0..n).map(|_| 0.7 + 0.5 * rng.uniform()).collect();
    let rfac: Vec<f32> = (0..m).map(|_| 0.5 + rng.uniform()).collect();
    let eps = 1e-5;

    // Plain GEMM.
    ok &= line("gemm", cuda::gemm(&a, &b).max_abs_diff(&kernels::gemm(&a, false, &b, false)), tol);

    // Kernel 4.
    let (gd, go, gr) = cuda::gemm_residual_partial_rms(&a, &b, &c, &gamma, eps);
    let (cd, co, cr) = kernels::gemm_residual_partial_rms(&a, &b, &c, &gamma, eps);
    ok &= line("gemm_residual_partial_rms (D)", gd.max_abs_diff(&cd), tol);
    ok &= line("gemm_residual_partial_rms (O)", go.max_abs_diff(&co), tol);
    ok &= line("gemm_residual_partial_rms (r)", maxdiff(&gr, &cr), tol);

    // Kernel 5.
    ok &= line(
        "gemm_rmsnorm",
        cuda::gemm_rmsnorm(&a, &b, &rfac).max_abs_diff(&kernels::gemm_rmsnorm(&a, &b, &rfac)),
        tol,
    );

    // Kernel 6.
    let (go6, gdp) = cuda::gemm_rmsnorm_swiglu(&a, &b, &rfac);
    let (co6, cdp) = kernels::gemm_rmsnorm_swiglu(&a, &b, &rfac);
    ok &= line("gemm_rmsnorm_swiglu (O)", go6.max_abs_diff(&co6), tol);
    ok &= line("gemm_rmsnorm_swiglu (D')", gdp.max_abs_diff(&cdp), tol);

    // Kernel 1: RoPE.
    let (mut cos, mut sin) = (Mat::zeros(m, n), Mat::zeros(m, n));
    for i in 0..m {
        for p in 0..n / 2 {
            let ang = i as f32 * 10000f32.powf(-2.0 * (p % 8) as f32 / 16.0);
            cos.set(i, 2 * p, ang.cos());
            cos.set(i, 2 * p + 1, ang.cos());
            sin.set(i, 2 * p, ang.sin());
            sin.set(i, 2 * p + 1, ang.sin());
        }
    }
    ok &= line(
        "gemm_rope",
        cuda::gemm_rope(&a, &b, &cos, &sin).max_abs_diff(&kernels::gemm_rope(&a, &b, &cos, &sin)),
        tol,
    );

    // Kernel 2: SwiGLU.
    ok &= line(
        "gemm_swiglu",
        cuda::gemm_swiglu(&a, &b).max_abs_diff(&kernels::gemm_swiglu(&a, &b)),
        tol,
    );

    // Kernel 8: cross-entropy.
    let targets: Vec<usize> = (0..m).map(|i| (i * 7 + 3) % n).collect();
    let (_, g_loss) = cuda::gemm_rmsnorm_ce(&a, &b, &rfac, &targets);
    let (_, _, c_loss) = kernels::gemm_rmsnorm_partial_ce(&a, &b, &rfac, &targets);
    ok &= line("gemm_rmsnorm_ce (loss)", maxdiff(&g_loss, &c_loss), tol);

    // ---- Benchmark: GEMM-Residual-RMSNorm, GPU vs CPU ----
    println!("\n== Benchmark: gemm_residual_partial_rms (Kernel 4) ==");
    for &d in &[256usize, 768] {
        let ba = randmat(&mut rng, d, d, 0.1);
        let bb = randmat(&mut rng, d, d, 0.1);
        let bc = randmat(&mut rng, d, d, 0.1);
        let bg: Vec<f32> = vec![1.0; d];
        let flop = 2.0 * (d as f64).powi(3);

        let t = Instant::now();
        let _ = kernels::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps);
        let cpu = t.elapsed().as_secs_f64();

        let t = Instant::now();
        let _ = cuda::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps);
        let gpu = t.elapsed().as_secs_f64();

        println!(
            "    {:>4}^3 : CPU {:>8.3}s ({:>6.2} GFLOP/s) | GPU {:>8.4}s ({:>7.1} GFLOP/s) | {:>6.1}x",
            d,
            cpu,
            flop / cpu / 1e9,
            gpu,
            flop / gpu / 1e9,
            cpu / gpu
        );
    }
    // GPU-only at a larger size the naive CPU path would be too slow for.
    for &d in &[2048usize] {
        let ba = randmat(&mut rng, d, d, 0.05);
        let bb = randmat(&mut rng, d, d, 0.05);
        let bc = randmat(&mut rng, d, d, 0.05);
        let bg: Vec<f32> = vec![1.0; d];
        let t = Instant::now();
        let _ = cuda::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps);
        let gpu = t.elapsed().as_secs_f64();
        println!(
            "    {:>4}^3 : GPU {:>8.4}s ({:>7.1} GFLOP/s)  [CPU skipped - too slow]",
            d,
            gpu,
            2.0 * (d as f64).powi(3) / gpu / 1e9
        );
    }

    println!();
    if ok {
        println!("ALL CUDA KERNELS MATCH THE CPU REFERENCE. GPU backend is live.");
    } else {
        println!("SOME CUDA KERNELS DISAGREE WITH THE CPU REFERENCE - see above.");
        std::process::exit(1);
    }
}
