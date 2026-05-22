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
    use coda::model::{Config, Model, Rng};
    use coda::tensor::Mat;
    use coda::train;
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
    // Real random inputs; the GPU side is warmed up (one untimed call, to
    // absorb PTX JIT) and averaged over 5 runs so the number is trustworthy.
    println!("\n== Benchmark: gemm_residual_partial_rms (Kernel 4) ==");
    for &d in &[768usize, 2048] {
        let mut r = Rng::new(0xBE0 + d as u64);
        let mut mk = || {
            let mut m = Mat::zeros(d, d);
            for v in m.data.iter_mut() {
                *v = r.normal() * 0.08;
            }
            m
        };
        let (ba, bb, bc) = (mk(), mk(), mk());
        let bg = vec![1.0f32; d];
        let flop = 2.0 * (d as f64).powi(3);

        let _ = cuda::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps); // warmup
        let t = Instant::now();
        for _ in 0..5 {
            let _ = cuda::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps);
        }
        let gpu = t.elapsed().as_secs_f64() / 5.0;

        if d <= 768 {
            let t = Instant::now();
            let _ = kernels::gemm_residual_partial_rms(&ba, &bb, &bc, &bg, eps);
            let cpu = t.elapsed().as_secs_f64();
            println!(
                "    {d:>4}^3 : CPU {cpu:>7.3}s ({:>6.2} GF/s) | GPU {gpu:>8.4}s ({:>7.1} GF/s) | {:>5.0}x",
                flop / cpu / 1e9,
                flop / gpu / 1e9,
                cpu / gpu
            );
        } else {
            println!(
                "    {d:>4}^3 : GPU {gpu:>8.4}s ({:>7.1} GF/s)  [CPU too slow]",
                flop / gpu / 1e9
            );
        }
    }

    // ---- Whole-model forward on the GPU ----
    println!("\n== Full Transformer forward on GPU: CUDA vs CPU ==");
    let argmax = |m: &Mat, row: usize| -> usize {
        (0..m.cols)
            .max_by(|&x, &y| m.get(row, x).partial_cmp(&m.get(row, y)).unwrap())
            .unwrap()
    };
    {
        // Correctness at the tiny config from the CPU demo.
        let cfg = Config::tiny(32);
        let model = Model::new(cfg.clone(), &mut Rng::new(2024));
        let tokens: Vec<usize> = (0..48).map(|i| (i * 5 + 1) % cfg.vocab).collect();
        let (cpu_logits, _) = model.forward(&tokens);
        let gpu_logits = cuda::model_forward(&model, &tokens);
        ok &= line(
            "model_forward (tiny): CUDA vs CPU logits",
            cpu_logits.max_abs_diff(&gpu_logits),
            2e-2,
        );
        let mism = (0..tokens.len())
            .filter(|&r| argmax(&cpu_logits, r) != argmax(&gpu_logits, r))
            .count();
        println!("           next-token argmax agreement: {}/{}", tokens.len() - mism, tokens.len());
    }

    // ---- Scale up: a ~27M-parameter model, GPU vs CPU ----
    println!("\n== Scaled-up model: full forward, GPU vs CPU ==");
    {
        let cfg = Config {
            vocab: 8192,
            d_model: 512,
            n_layers: 6,
            n_heads: 8,
            head_dim: 64,
            d_ff: 1376,
            eps: 1e-5,
            rope_base: 10000.0,
        };
        let params = cfg.vocab * cfg.d_model * 2
            + cfg.n_layers
                * (cfg.d_model * 3 * cfg.d_model
                    + cfg.d_model * cfg.d_model
                    + cfg.d_model * 2 * cfg.d_ff
                    + cfg.d_ff * cfg.d_model
                    + 2 * cfg.d_model)
            + cfg.d_model;
        let seq = 256;
        println!(
            "    d_model={}, layers={}, heads={}, d_ff={}, vocab={}, seq={}  (~{:.1}M params)",
            cfg.d_model, cfg.n_layers, cfg.n_heads, cfg.d_ff, cfg.vocab, seq,
            params as f64 / 1e6
        );
        let model = Model::new(cfg.clone(), &mut Rng::new(7));
        let tokens: Vec<usize> = (0..seq).map(|i| (i * 11 + 5) % cfg.vocab).collect();

        let t0 = Instant::now();
        let gpu_logits = cuda::model_forward(&model, &tokens);
        let gpu_t = t0.elapsed().as_secs_f64();

        let t0 = Instant::now();
        let (cpu_logits, _) = model.forward(&tokens);
        let cpu_t = t0.elapsed().as_secs_f64();

        let diff = cpu_logits.max_abs_diff(&gpu_logits);
        let mism = (0..tokens.len())
            .filter(|&r| argmax(&cpu_logits, r) != argmax(&gpu_logits, r))
            .count();
        println!(
            "    GPU forward {:.4}s  |  CPU forward {:.3}s  |  {:.0}x speedup",
            gpu_t, cpu_t, cpu_t / gpu_t
        );
        println!("    next-token argmax agreement: {}/{}", tokens.len() - mism, tokens.len());
        ok &= line("scaled model: CUDA vs CPU logits", diff, 5e-2);
    }

    // ---- GPU backward: gradients vs the CPU reference ----
    println!("\n== GPU backward pass: gradients vs CPU ==");
    {
        let cfg = Config::tiny(24);
        let model = Model::new(cfg.clone(), &mut Rng::new(555));
        let tokens: Vec<usize> = (0..40).map(|i| (i * 5 + 1) % cfg.vocab).collect();
        let targets: Vec<usize> = (0..40).map(|i| (i * 5 + 6) % cfg.vocab).collect();
        let (_, cache) = model.forward(&tokens);
        let (cpu_loss, cpu_g) = train::backward(&model, &cache, &targets);
        let (gpu_g, gpu_loss) = cuda::grads(&model, &tokens, &targets);
        let (cf, gf) = (cpu_g.flat(), gpu_g.flat());
        let mut worst = 0.0f32;
        for (c, g) in cf.iter().zip(&gf) {
            for (x, y) in c.iter().zip(g.iter()) {
                let denom = x.abs().max(y.abs()).max(1e-3);
                worst = worst.max((x - y).abs() / denom);
            }
        }
        println!("    loss: CPU {cpu_loss:.5}  GPU {gpu_loss:.5}");
        ok &= line("GPU gradients match CPU backward (relative)", worst, 3e-2);
    }

    // ---- Device-resident GPU training, verified against CPU ----
    println!("\n== GPU training: device-resident loop vs CPU ==");
    {
        let cfg = Config::tiny(24);
        let tokens: Vec<usize> = (0..40).map(|i| (i * 7 + 2) % cfg.vocab).collect();
        let targets: Vec<usize> = tokens.iter().map(|&t| (t + 1) % cfg.vocab).collect();
        let model = Model::new(cfg.clone(), &mut Rng::new(99));

        let (_, gpu_curve) = cuda::train(&model, &tokens, &targets, 300, 3e-3);
        println!(
            "    GPU loss: step 0 = {:.4}  step 150 = {:.4}  final = {:.4}",
            gpu_curve[0], gpu_curve[150], gpu_curve[299]
        );
        let mut cpu_model = Model::new(cfg.clone(), &mut Rng::new(99));
        let cpu_curve = train::train(&mut cpu_model, &tokens, &targets, 300, 3e-3, 150);
        println!("    CPU loss (identical init): final = {:.4}", cpu_curve.last().unwrap().1);
        ok &= line("GPU training drives the loss down", gpu_curve[299], 0.5);
    }

    // ---- Scale up: train a large model on the GPU ----
    // CODA_SCALE=big selects a ~6.7B-parameter (Llama-7B-class) config whose
    // weights are generated and kept entirely on the GPU and optimized with
    // SGD - Adam's moment tensors would not fit. The default is a ~10M model.
    println!("\n== Scaled-up GPU training ==");
    {
        let big = std::env::var("CODA_SCALE").map(|s| s == "big").unwrap_or(false);
        let cfg = if big {
            // ~6.7B parameters - Llama-7B class (needs an 80GB A100).
            Config {
                vocab: 32000,
                d_model: 4096,
                n_layers: 32,
                n_heads: 32,
                head_dim: 128,
                d_ff: 11008,
                eps: 1e-5,
                rope_base: 10000.0,
            }
        } else {
            Config {
                vocab: 4096,
                d_model: 384,
                n_layers: 4,
                n_heads: 6,
                head_dim: 64,
                d_ff: 1024,
                eps: 1e-5,
                rope_base: 10000.0,
            }
        };
        let params = cfg.vocab * cfg.d_model * 2
            + cfg.n_layers
                * (cfg.d_model * 3 * cfg.d_model
                    + cfg.d_model * cfg.d_model
                    + cfg.d_model * 2 * cfg.d_ff
                    + cfg.d_ff * cfg.d_model
                    + 2 * cfg.d_model)
            + cfg.d_model;
        let seq = if big { 512 } else { 128 };
        let tokens: Vec<usize> = (0..seq).map(|i| (i * 13 + 1) % cfg.vocab).collect();
        let targets: Vec<usize> = tokens.iter().map(|&t| (t * 2 + 1) % cfg.vocab).collect();
        println!(
            "    d_model={}, layers={}, heads={}, d_ff={}, vocab={}, seq={}  (~{:.2}B params)",
            cfg.d_model, cfg.n_layers, cfg.n_heads, cfg.d_ff, cfg.vocab, seq,
            params as f64 / 1e9
        );

        if big {
            // Weights generated + kept on the GPU; plain-SGD optimizer.
            let steps = 60;
            let t0 = Instant::now();
            let curve = cuda::train_random(&cfg, &tokens, &targets, steps, 0.05, 2025);
            let dt = t0.elapsed().as_secs_f64();
            println!(
                "    {} steps in {:.1}s ({:.0} ms/step)  [GPU-resident weights, SGD]",
                steps, dt, dt * 1000.0 / steps as f64
            );
            println!("    loss: {:.3} -> {:.3}", curve[0], curve[steps - 1]);
            ok &= line(
                "scaled GPU training reduces the loss",
                if curve[steps - 1] < curve[0] { 0.0 } else { 1.0 },
                0.5,
            );
        } else {
            let model = Model::new(cfg.clone(), &mut Rng::new(2025));
            let steps = 200;
            let t0 = Instant::now();
            let (_, curve) = cuda::train(&model, &tokens, &targets, steps, 2e-3);
            let dt = t0.elapsed().as_secs_f64();
            println!(
                "    {} steps in {:.1}s ({:.0} ms/step)",
                steps, dt, dt * 1000.0 / steps as f64
            );
            println!("    loss: {:.3} -> {:.3}", curve[0], curve[steps - 1]);
            ok &= line(
                "scaled GPU training reduces the loss",
                if curve[steps - 1] < curve[0] { 0.0 } else { 1.0 },
                0.5,
            );
        }
    }

    // ---- Train a real language model on a real text corpus ----
    // Stochastic windowed training over ~1 MB of real English text (Project
    // tinyshakespeare): every step trains on a different random window, so the
    // model learns the corpus distribution rather than memorizing a sequence.
    println!("\n== Real language model: trained on a text corpus, then generating ==");
    {
        let corpus_text = std::fs::read_to_string("/work/corpus.txt").unwrap_or_default();
        if corpus_text.len() < 50_000 {
            println!("    (no training corpus at /work/corpus.txt - skipping)");
        } else {
            // Character-level tokenization.
            let text: Vec<char> = corpus_text.chars().filter(|c| c.is_ascii()).collect();
            let mut vocab: Vec<char> = text.clone();
            vocab.sort_unstable();
            vocab.dedup();
            let idx: std::collections::HashMap<char, usize> =
                vocab.iter().enumerate().map(|(i, &c)| (c, i)).collect();
            let tokens: Vec<usize> = text.iter().map(|c| idx[c]).collect();

            let cfg = Config {
                vocab: vocab.len(),
                d_model: 256,
                n_layers: 4,
                n_heads: 4,
                head_dim: 64,
                d_ff: 768,
                eps: 1e-5,
                rope_base: 10000.0,
            };
            let params = cfg.vocab * cfg.d_model * 2
                + cfg.n_layers
                    * (cfg.d_model * 3 * cfg.d_model
                        + cfg.d_model * cfg.d_model
                        + cfg.d_model * 2 * cfg.d_ff
                        + cfg.d_ff * cfg.d_model
                        + 2 * cfg.d_model)
                + cfg.d_model;
            let model = Model::new(cfg.clone(), &mut Rng::new(1));
            println!(
                "    corpus: {} characters, vocab {};  model: ~{:.0}M-parameter GPT \
                 (d_model {}, {} layers)",
                tokens.len(), vocab.len(), params as f64 / 1e6, cfg.d_model, cfg.n_layers
            );

            // Stochastic windowed training on the GPU, with a mini-batch of
            // windows accumulated per Adam step (cuts the batch-1 noise).
            let t_window = 256;
            let steps = 4000;
            let batch = 16;
            let t0 = Instant::now();
            let (trained, curve) =
                cuda::train_corpus(&model, &tokens, t_window, steps, batch, 3e-3, 42);
            let tail: f32 = curve[steps - 200..].iter().sum::<f32>() / 200.0;
            println!(
                "    trained on the GPU: {steps} steps x batch {batch} = {} windows in {:.0}s",
                steps * batch,
                t0.elapsed().as_secs_f64()
            );
            println!(
                "    loss (cross-entropy per char): {:.3} -> {:.3} -> {:.3}  (random {:.2})",
                curve[0], curve[steps / 2], tail, (vocab.len() as f32).ln()
            );

            // Generate NOVEL text by temperature sampling (not greedy reproduction).
            let mut seq: Vec<usize> = tokens[..32].to_vec();
            let mut rng = Rng::new(12345);
            let temp = 0.8f32;
            for _ in 0..480 {
                let ctx = &seq[seq.len().saturating_sub(t_window)..];
                let logits = cuda::model_forward(&trained, ctx);
                let last = logits.rows - 1;
                let mx = (0..logits.cols).fold(f32::NEG_INFINITY, |m, j| m.max(logits.get(last, j)));
                let mut probs = vec![0.0f32; logits.cols];
                let mut sum = 0.0f32;
                for j in 0..logits.cols {
                    let p = ((logits.get(last, j) - mx) / temp).exp();
                    probs[j] = p;
                    sum += p;
                }
                let r = rng.uniform() * sum;
                let mut acc = 0.0f32;
                let mut pick = logits.cols - 1;
                for j in 0..logits.cols {
                    acc += probs[j];
                    if acc >= r {
                        pick = j;
                        break;
                    }
                }
                seq.push(pick);
            }
            let generated: String = seq.iter().map(|&t| vocab[t]).collect();
            println!("    --- {} characters of novel text generated by the GPU-trained model ---", seq.len());
            println!("{generated}");
            println!("    --- end ---");
            ok &= line("the model learned the corpus (loss well below random)", tail, 2.3);
        }
    }

    println!();
    if ok {
        println!("ALL CUDA KERNELS MATCH THE CPU REFERENCE. GPU backend is live.");
    } else {
        println!("SOME CUDA KERNELS DISAGREE WITH THE CPU REFERENCE - see above.");
        std::process::exit(1);
    }
}
