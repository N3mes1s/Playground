//! `code2lora` CLI: turn a GitHub/local repository into a PEFT LoRA adapter for
//! a frozen base LLM, then verify the artifact attaches to the real model.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use code2lora::embedder::{encode_repo, HashEmbedder};
use code2lora::hypernet::{HyperNet, HyperNetConfig};
use code2lora::lora::{export_peft, load_peft_safetensors};
use code2lora::model::{ModelSpec, MODULE_TYPES};
use code2lora::tensor::frob;

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
        Cmd::Encode { repo } => cmd_encode(&repo),
        Cmd::Generate {
            repo,
            out,
            config,
            seed,
        } => cmd_generate(&repo, &out, &config, seed),
        Cmd::Verify { adapter, config } => cmd_verify(&adapter, &config),
        Cmd::Info { config } => cmd_info(&config),
    }
}

fn cmd_encode(repo: &Path) -> Result<()> {
    let emb = HashEmbedder::default();
    let (e, stats) = encode_repo(repo, &emb)?;
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

fn cmd_generate(repo: &Path, out: &Path, config: &Option<PathBuf>, seed: u64) -> Result<()> {
    let spec = load_spec(config)?;
    let emb = HashEmbedder::default();
    println!("encoding {} ...", repo.display());
    let (e, stats) = encode_repo(repo, &emb)?;
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
