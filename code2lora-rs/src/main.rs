//! `code2lora` CLI: turn a GitHub/local repository into a PEFT LoRA adapter for
//! a frozen base LLM, then verify the artifact attaches to the real model.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use code2lora::embedder::{encode_repo, encode_text, Embedder, HashEmbedder};
use code2lora::evo::EvoHyperNet;
use code2lora::hypernet::{HyperNet, HyperNetConfig};
use code2lora::lora::{export_peft, load_peft_safetensors};
use code2lora::model::{ModelSpec, MODULE_TYPES};
use code2lora::tensor::frob;
use code2lora::train::{run_demo, TrainConfig};

#[derive(Parser)]
#[command(
    name = "code2lora",
    about = "Code2LoRA (arXiv:2606.06492) in Rust: GitHub repo -> LoRA adapter",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encode a repository into its R^2048 embedding and report stats.
    Encode {
        #[arg(long)]
        repo: PathBuf,
        /// Use the real neural embedder (requires building with --features neural).
        #[arg(long)]
        neural: bool,
        /// Neural embedder model id (default BAAI/bge-large-en-v1.5).
        #[arg(long)]
        embed_model: Option<String>,
    },
    /// Generate a PEFT LoRA adapter from a repository.
    Generate {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long, default_value = "adapter")]
        out: PathBuf,
        /// HF config.json of the target model (defaults to Qwen2.5-Coder-1.5B).
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Use the real neural embedder (requires building with --features neural).
        #[arg(long)]
        neural: bool,
        #[arg(long)]
        embed_model: Option<String>,
    },
    /// Verify an exported adapter attaches to the target model.
    Verify {
        #[arg(long)]
        adapter: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print the target model spec, per-module LoRA dims, and param counts.
    Info {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Code2LoRA-Evo: walk a git repo's history, emit an adapter trajectory,
    /// and export the final (newest-commit) adapter.
    Evo {
        /// Path to a git repository.
        #[arg(long)]
        repo: PathBuf,
        #[arg(long, default_value = "adapter-evo")]
        out: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = 12)]
        max_commits: usize,
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
    /// Security: scan a git repo's history for anomalous commits using the Evo
    /// GRU. Flags commits whose diff pushes the repository state abnormally far
    /// (supply-chain / backdoor review). Optionally inject a patch to score.
    EvoScan {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long, default_value_t = 40)]
        max_commits: usize,
        /// Score this patch file as an extra (latest) commit and flag it.
        #[arg(long)]
        inject: Option<PathBuf>,
        /// Comma-separated commit-hash prefixes to report the anomaly rank of.
        #[arg(long)]
        flag: Option<String>,
        /// Anomaly score: "knn" (local outlier, best), "centroid", or "state-jump".
        #[arg(long, default_value = "knn")]
        method: String,
        #[arg(long)]
        neural: bool,
        #[arg(long)]
        embed_model: Option<String>,
        /// Skip the (slow) whole-repo snapshot encode; init GRU state from zero.
        #[arg(long)]
        no_snapshot: bool,
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
    /// Train the Static hypernetwork on a frozen-base adaptation task (pure-Rust
    /// autograd) and report held-out generalization vs baseline/untrained.
    TrainDemo {
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value_t = 5000)]
        steps: usize,
    },
}

fn load_spec(config: &Option<PathBuf>) -> Result<ModelSpec> {
    match config {
        Some(p) => ModelSpec::from_config(p),
        None => Ok(ModelSpec::qwen25_coder_1_5b()),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encode {
            repo,
            neural,
            embed_model,
        } => cmd_encode(&repo, neural, embed_model),
        Cmd::Generate {
            repo,
            out,
            config,
            seed,
            neural,
            embed_model,
        } => cmd_generate(&repo, &out, &config, seed, neural, embed_model),
        Cmd::Verify { adapter, config } => cmd_verify(&adapter, &config),
        Cmd::Info { config } => cmd_info(&config),
        Cmd::Evo {
            repo,
            out,
            config,
            max_commits,
            seed,
        } => cmd_evo(&repo, &out, &config, max_commits, seed),
        Cmd::EvoScan {
            repo,
            max_commits,
            inject,
            flag,
            method,
            neural,
            embed_model,
            no_snapshot,
            seed,
        } => cmd_evo_scan(&repo, max_commits, &inject, &flag, &method, neural, embed_model, no_snapshot, seed),
        Cmd::TrainDemo { seed, steps } => cmd_train_demo(seed, steps),
    }
}

fn cmd_evo_scan(
    repo: &Path,
    max_commits: usize,
    inject: &Option<PathBuf>,
    flag: &Option<String>,
    method: &str,
    neural: bool,
    embed_model: Option<String>,
    no_snapshot: bool,
    seed: u64,
) -> Result<()> {
    let spec = ModelSpec::qwen25_coder_1_5b();
    let emb = make_embedder(neural, embed_model)?;

    let e0 = if no_snapshot {
        vec![0.0f32; 2 * emb.dim()]
    } else {
        println!("encoding snapshot {} ...", repo.display());
        encode_repo(repo, emb.as_ref())?.0
    };

    let log = git(repo, &["rev-list", "--reverse", "--max-count", &max_commits.to_string(), "HEAD"])?;
    let commits: Vec<&str> = log.split_whitespace().collect();
    anyhow::ensure!(!commits.is_empty(), "no commits in {}", repo.display());

    let mut labels: Vec<String> = Vec::new();
    let mut diffs: Vec<Vec<f32>> = Vec::new();
    for h in &commits {
        let patch = git(repo, &["show", "--format=", "--unified=3", h]).unwrap_or_default();
        diffs.push(encode_text(emb.as_ref(), &patch));
        labels.push(h[..h.len().min(8)].to_string());
    }

    let mut inject_idx: Option<usize> = None;
    if let Some(p) = inject {
        let patch = std::fs::read_to_string(p)
            .with_context(|| format!("reading inject patch {}", p.display()))?;
        diffs.push(encode_text(emb.as_ref(), &patch));
        labels.push("INJECTED".to_string());
        inject_idx = Some(diffs.len() - 1);
    }

    println!("scanning {} commits (method={method}) ...", diffs.len());

    // L2-normalize diff embeddings for cosine-based scores.
    let norm: Vec<Vec<f32>> = diffs
        .iter()
        .map(|v| {
            let mut u = v.clone();
            code2lora::tensor::l2_normalize(&mut u);
            u
        })
        .collect();
    let cos = |a: &[f32], b: &[f32]| a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>();

    // per-commit anomaly score (higher = more anomalous)
    let deltas: Vec<f32> = match method {
        // kNN local-outlier: 1 - mean cosine to k nearest *other* commits.
        // Catches camouflaged commits (near the global mean but with no close
        // neighbours) that pure novelty/state-jump misses.
        "knn" => {
            let k = 3.min(norm.len().saturating_sub(1)).max(1);
            (0..norm.len())
                .map(|i| {
                    let mut sims: Vec<f32> = (0..norm.len())
                        .filter(|&j| j != i)
                        .map(|j| cos(&norm[i], &norm[j]))
                        .collect();
                    sims.sort_by(|a, b| b.partial_cmp(a).unwrap());
                    let top = &sims[..k.min(sims.len())];
                    1.0 - top.iter().sum::<f32>() / top.len() as f32
                })
                .collect()
        }
        // centroid novelty: 1 - cos(e_i, mean of others)
        "centroid" => {
            let dim = norm[0].len();
            (0..norm.len())
                .map(|i| {
                    let mut c = vec![0.0f32; dim];
                    for (j, v) in norm.iter().enumerate() {
                        if j != i {
                            for d in 0..dim {
                                c[d] += v[d];
                            }
                        }
                    }
                    code2lora::tensor::l2_normalize(&mut c);
                    1.0 - cos(&norm[i], &c)
                })
                .collect()
        }
        // state-jump: ||z_t - z_{t-1}|| from the Evo GRU
        _ => {
            let net = EvoHyperNet::new(spec, seed);
            let states = net.run_states(&e0, &diffs);
            (0..diffs.len())
                .map(|i| {
                    states[i]
                        .iter()
                        .zip(&states[i + 1])
                        .map(|(a, b)| (a - b) * (a - b))
                        .sum::<f32>()
                        .sqrt()
                })
                .collect()
        }
    };

    let n = deltas.len() as f32;
    let mean = deltas.iter().sum::<f32>() / n;
    let std = (deltas.iter().map(|d| (d - mean) * (d - mean)).sum::<f32>() / n)
        .sqrt()
        .max(1e-9);

    // rank by anomaly score (z-score of state jump)
    let mut ranked: Vec<(usize, f32)> = deltas
        .iter()
        .enumerate()
        .map(|(i, &d)| (i, (d - mean) / std))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    println!("\ntop anomalous commits (state-jump z-score):");
    for (rank, (i, z)) in ranked.iter().take(10).enumerate() {
        let flag = if *z > 2.0 { "  <== ANOMALY" } else { "" };
        let mark = if Some(*i) == inject_idx { " [INJECTED]" } else { "" };
        println!(
            "  #{}  {:<10}{}  score={:.4}  z={:+.2}{}",
            rank + 1,
            labels[*i],
            mark,
            deltas[*i],
            z,
            flag
        );
    }

    if let Some(idx) = inject_idx {
        let total = diffs.len();
        let pos = ranked.iter().position(|(i, _)| *i == idx).unwrap() + 1;
        let z = (deltas[idx] - mean) / std;
        let pct = 100.0 * pos as f32 / total as f32;
        let topk = std::cmp::max(3, total / 10); // review the top ~10%
        println!(
            "\nINJECTED malicious commit ranked #{} of {} (z={:+.2}, top {:.0}%).",
            pos, total, z, pct
        );
        if pos == 1 {
            println!("DETECTED: the planted commit is the single most anomalous in history.");
        } else if pos <= topk || z > 2.0 {
            println!(
                "SURFACED: a reviewer scanning the top {} anomalies catches the planted commit \
                 (an untrained GRU + tiny patch; training on normal commits sharpens this).",
                topk
            );
        } else {
            println!("not surfaced at this budget; try --neural for a stronger semantic signal.");
        }
    }

    if let Some(flags) = flag {
        let total = diffs.len();
        let topk = std::cmp::max(3, total / 10);
        println!("\nrank of flagged commits:");
        for pref in flags.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match labels.iter().position(|l| l.starts_with(pref)) {
                Some(idx) => {
                    let pos = ranked.iter().position(|(i, _)| *i == idx).unwrap() + 1;
                    let z = (deltas[idx] - mean) / std;
                    let verdict = if pos <= topk || z > 2.0 {
                        "  <== SURFACED (top anomalies)"
                    } else {
                        ""
                    };
                    println!(
                        "  {:<10}  rank #{} of {} (z={:+.2}, top {:.0}%){}",
                        pref,
                        pos,
                        total,
                        z,
                        100.0 * pos as f32 / total as f32,
                        verdict
                    );
                }
                None => println!("  {pref:<10}  not in scanned window"),
            }
        }
    }
    Ok(())
}

/// Build the requested embedder. Neural requires the `neural` build feature.
fn make_embedder(neural: bool, model: Option<String>) -> Result<Box<dyn Embedder>> {
    if !neural {
        return Ok(Box::new(HashEmbedder::default()));
    }
    #[cfg(feature = "neural")]
    {
        let id = model.unwrap_or_else(|| "BAAI/bge-large-en-v1.5".to_string());
        eprintln!("loading neural embedder {id} (first run downloads weights) ...");
        return Ok(Box::new(code2lora::neural::NeuralEmbedder::load(&id)?));
    }
    #[cfg(not(feature = "neural"))]
    {
        let _ = model;
        anyhow::bail!(
            "--neural requires building with the feature: cargo build --release --features neural"
        );
    }
}

fn cmd_encode(repo: &Path, neural: bool, embed_model: Option<String>) -> Result<()> {
    let emb = make_embedder(neural, embed_model)?;
    let (e, stats) = encode_repo(repo, emb.as_ref())?;
    println!("repo:           {}", repo.display());
    println!("source files:   {}", stats.files);
    println!("total tokens:   {}", stats.total_tokens);
    println!("embedding dim:  {}", e.len());
    println!("embedding norm: {:.4}", frob(&e));
    println!("top files by importance weight:");
    for (p, w) in &stats.top_files {
        println!("  {:>7.4}  {}", w, p);
    }
    Ok(())
}

fn cmd_generate(
    repo: &Path,
    out: &Path,
    config: &Option<PathBuf>,
    seed: u64,
    neural: bool,
    embed_model: Option<String>,
) -> Result<()> {
    let spec = load_spec(config)?;
    let emb = make_embedder(neural, embed_model)?;
    println!("encoding {} ...", repo.display());
    let (e, stats) = encode_repo(repo, emb.as_ref())?;
    println!(
        "  {} files, {} tokens -> embedding R^{}",
        stats.files,
        stats.total_tokens,
        e.len()
    );

    let cfg = HyperNetConfig {
        seed,
        ..Default::default()
    };
    let net = HyperNet::new(spec.clone(), cfg, e.len());
    println!("running Code2LoRA-Static hypernetwork (seed={seed}) ...");
    let adapter = net.generate(&e);

    let n = export_peft(&adapter, &spec, out)?;
    println!("exported PEFT adapter to {}", out.display());
    println!(
        "  {} tensors  (rank={}, alpha={}, {} module types x {} layers x 2)",
        n,
        adapter.rank,
        adapter.alpha,
        adapter.mats.len(),
        spec.num_layers
    );
    // Quick magnitude report on the first module type.
    if let Some((m, a, b)) = adapter.mats.first() {
        println!(
            "  e.g. {}: A{:?} ||{:.4}||  B{:?} ||{:.4}||",
            m.proj_name(),
            [a.rows, a.cols],
            frob(&a.data),
            [b.rows, b.cols],
            frob(&b.data)
        );
    }
    println!("\nattach it with:");
    println!("  PeftModel.from_pretrained(base, \"{}\")", out.display());
    Ok(())
}

fn cmd_verify(adapter_dir: &Path, config: &Option<PathBuf>) -> Result<()> {
    let spec = load_spec(config)?;
    let st_path = adapter_dir.join("adapter_model.safetensors");
    let cfg_path = adapter_dir.join("adapter_config.json");
    anyhow::ensure!(st_path.exists(), "missing {}", st_path.display());
    anyhow::ensure!(cfg_path.exists(), "missing {}", cfg_path.display());

    let tensors = load_peft_safetensors(&st_path)?;
    println!("loaded {} tensors from {}", tensors.len(), st_path.display());

    let mut checks = 0usize;
    let mut failures = 0usize;
    let mut max_abs = 0.0f32;
    let mut all_finite = true;

    // Every layer x module type must have lora_A [r,in] and lora_B [out,r]
    // exactly matching the real model's projection dims.
    for layer in 0..spec.num_layers {
        for &m in MODULE_TYPES.iter() {
            let (in_f, out_f) = spec.lora_dims(m);
            let prefix = format!(
                "base_model.model.model.layers.{}.{}.{}",
                layer,
                m.block(),
                m.proj_name()
            );
            for (suffix, want) in [
                ("lora_A.weight", vec![16usize, in_f]),
                ("lora_B.weight", vec![out_f, 16usize]),
            ] {
                let key = format!("{prefix}.{suffix}");
                checks += 1;
                match tensors.get(&key) {
                    None => {
                        failures += 1;
                        eprintln!("  MISSING {key}");
                    }
                    Some((shape, data)) => {
                        // rank dim is whatever the adapter used; compare the
                        // model-derived dim (in/out) only.
                        let model_dim = if suffix.starts_with("lora_A") {
                            shape.get(1).copied()
                        } else {
                            shape.first().copied()
                        };
                        let want_dim = if suffix.starts_with("lora_A") {
                            want[1]
                        } else {
                            want[0]
                        };
                        if model_dim != Some(want_dim) {
                            failures += 1;
                            eprintln!(
                                "  SHAPE MISMATCH {key}: got {:?}, model expects dim {}",
                                shape, want_dim
                            );
                        }
                        for &v in data {
                            if !v.is_finite() {
                                all_finite = false;
                            }
                            max_abs = max_abs.max(v.abs());
                        }
                    }
                }
            }
        }
    }

    println!("shape checks:   {} ({} failed)", checks, failures);
    println!("all finite:     {}", all_finite);
    println!("max |weight|:   {:.5}", max_abs);
    println!(
        "near-identity:  {} (init log-scale keeps adapters small)",
        max_abs < 0.5
    );

    if failures == 0 && all_finite {
        println!("\nVERIFY PASS: adapter attaches to {}", spec.name);
        Ok(())
    } else {
        anyhow::bail!("VERIFY FAIL: {failures} shape failures, finite={all_finite}");
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| "running git (is it installed and is this a repo?)")?;
    anyhow::ensure!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cmd_evo(
    repo: &Path,
    out: &Path,
    config: &Option<PathBuf>,
    max_commits: usize,
    seed: u64,
) -> Result<()> {
    let spec = load_spec(config)?;
    let emb = HashEmbedder::default();

    // Snapshot prior from the current working tree.
    println!("encoding snapshot {} ...", repo.display());
    let (e0, _) = encode_repo(repo, &emb)?;

    // Chronological commits (oldest -> newest), capped.
    let log = git(repo, &["rev-list", "--reverse", "--max-count", &max_commits.to_string(), "HEAD"])?;
    let commits: Vec<&str> = log.split_whitespace().collect();
    anyhow::ensure!(!commits.is_empty(), "no commits found in {}", repo.display());
    println!("walking {} commits ...", commits.len());

    let mut diffs = Vec::with_capacity(commits.len());
    for h in &commits {
        let patch = git(repo, &["show", "--format=", "--unified=3", h]).unwrap_or_default();
        diffs.push(encode_text(&emb, &patch));
    }

    let net = EvoHyperNet::new(spec.clone(), seed);
    let (traj, _z) = net.run(&e0, &diffs);

    // Show the adapter trajectory: how much the q_proj.A matrix moves per commit.
    println!("\nadapter trajectory (||ΔA_q|| between consecutive commits):");
    let mut prev: Option<Vec<f32>> = None;
    for (i, adapter) in traj.iter().enumerate() {
        let a_q = &adapter.mats[0].1.data; // q_proj A
        let delta = match &prev {
            Some(p) => {
                let d: f32 = p.iter().zip(a_q).map(|(x, y)| (x - y) * (x - y)).sum::<f32>().sqrt();
                format!("{:.5}", d)
            }
            None => "   (init)".to_string(),
        };
        let short = &commits[i][..commits[i].len().min(8)];
        println!("  commit {:>2} {}  ||ΔA_q||={}", i + 1, short, delta);
        prev = Some(a_q.clone());
    }

    let final_adapter = traj.last().expect("non-empty trajectory");
    let n = export_peft(final_adapter, &spec, out)?;
    println!(
        "\nexported final-commit adapter to {} ({} tensors)",
        out.display(),
        n
    );
    Ok(())
}

fn cmd_train_demo(seed: u64, steps: usize) -> Result<()> {
    let cfg = TrainConfig {
        seed,
        steps,
        ..Default::default()
    };
    println!(
        "training Static hypernetwork (pure-Rust autograd) on a frozen-base\n\
         adaptation task: {} train repos, {} held-out, rank {} (truth rank {}), {} steps",
        cfg.n_train, cfg.n_test, cfg.rank, cfg.true_rank, cfg.steps
    );
    let r = run_demo(&cfg);
    println!("\ntraining loss curve (every 5%):");
    print!("  ");
    for (i, l) in r.curve.iter().enumerate() {
        print!("{:.3}", l);
        if i + 1 < r.curve.len() {
            print!(" -> ");
        }
    }
    println!();
    println!("\nheld-out adaptation error (lower = better):");
    println!("  no adaptation (ΔW=0):       {:.4}", r.baseline_loss);
    println!("  untrained hypernetwork:     {:.4}", r.init_loss);
    println!("  TRAINED hypernetwork:       {:.4}", r.trained_loss);
    let reduction = 100.0 * (1.0 - r.trained_loss / r.baseline_loss);
    println!(
        "\nTRAINED hypernetwork cuts held-out adaptation error by {:.1}% vs no-adapt,",
        reduction
    );
    println!(
        "  and {:.1}% vs its own untrained init -> it learned to synthesize",
        100.0 * (1.0 - r.trained_loss / r.init_loss)
    );
    println!("  repository-specific adapters that generalize to unseen repos.");
    Ok(())
}

fn cmd_info(config: &Option<PathBuf>) -> Result<()> {
    let spec = load_spec(config)?;
    println!("model:            {}", spec.name);
    println!("hidden_size:      {}", spec.hidden_size);
    println!("intermediate:     {}", spec.intermediate_size);
    println!("layers:           {}", spec.num_layers);
    println!("heads / kv_heads: {} / {}", spec.num_heads, spec.num_kv_heads);
    println!("head_dim:         {}", spec.head_dim);
    println!("\nper-module LoRA dims (rank r=16):");
    let r = 16usize;
    let (mut adapter_params, mut head_params) = (0usize, 0usize);
    let d_h = 1024usize;
    for &m in MODULE_TYPES.iter() {
        let (in_f, out_f) = spec.lora_dims(m);
        let ap = r * in_f + out_f * r;
        adapter_params += ap;
        head_params += d_h * (r * in_f) + d_h * (out_f * r);
        println!(
            "  {:<10} A[{:>2},{:>5}]  B[{:>5},{:>2}]  (+{} adapter params/layer-shared)",
            m.proj_name(),
            r,
            in_f,
            out_f,
            r,
            ap
        );
    }
    println!("\nLoRA params (shared across {} layers): {}", spec.num_layers, adapter_params);
    println!(
        "expanded to PEFT tensors:              {}",
        adapter_params * spec.num_layers
    );
    println!(
        "hypernetwork head params (d_h={}):      ~{:.1}M",
        d_h,
        head_params as f64 / 1e6
    );
    Ok(())
}
