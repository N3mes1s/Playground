use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ods_core::{Mode, Run};
use ods_lang::Registry;
use ods_lang_rust::RustAdapter;
use ods_recipes::{PromotionState, RecipeQuery, Store};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "ods",
    version,
    about = "Optimization Discovery System - CI-integrated, agent-driven perf wins across languages"
)]
struct Cli {
    /// Path to the recipe store (SQLite). Defaults to ./.ods/recipes.db.
    #[arg(long, env = "ODS_STORE", global = true)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover hot-primitive candidates in a repository.
    Scan {
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Execute the full optimization loop on a target.
    Run {
        repo: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long, value_enum, default_value_t = RunMode::Dev)]
        mode: RunMode,
        /// Wall-clock cap (seconds) in CI mode.
        #[arg(long, default_value_t = 900)]
        wall_cap_s: u64,
        /// Maximum API spend (USD) in CI mode.
        #[arg(long, default_value_t = 5.0)]
        spend_cap_usd: f64,
    },
    /// Measurement-only: bench a target without patching.
    Bench {
        repo: PathBuf,
        #[arg(long)]
        target: String,
    },
    /// Compatibility gate on an existing patch file.
    Verify {
        repo: PathBuf,
        #[arg(long)]
        patch: PathBuf,
    },
    /// Recipe corpus management.
    Recipes {
        #[command(subcommand)]
        action: RecipeAction,
    },
    /// GitHub integration (Actions one-shot / App webhook server).
    Ci {
        #[command(subcommand)]
        action: CiAction,
    },
    /// Regenerate the data-backed report for a prior run.
    Explain {
        run_id: String,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum RunMode {
    Dev,
    Ci,
}

#[derive(Subcommand, Debug)]
enum RecipeAction {
    List {
        #[arg(long)]
        language: Option<String>,
    },
    Show {
        id: String,
    },
    Import {
        path: PathBuf,
    },
    Export {
        out: PathBuf,
    },
    Promote {
        id: String,
        #[arg(long, value_enum)]
        to: RecipePromotion,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum RecipePromotion {
    Seed,
    Candidate,
    Validated,
    Corpus,
}

#[derive(Subcommand, Debug)]
enum CiAction {
    Action {
        repo: PathBuf,
    },
    Serve {
        #[arg(long, default_value_t = 8787)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let store_path = cli
        .store
        .clone()
        .unwrap_or_else(|| PathBuf::from(".ods/recipes.db"));

    match cli.command {
        Command::Scan { repo, json } => cmd_scan(&repo, json),
        Command::Run { repo, target, mode, wall_cap_s, spend_cap_usd } => {
            cmd_run(&repo, &target, mode, wall_cap_s, spend_cap_usd, &store_path)
        }
        Command::Bench { repo, target } => cmd_bench(&repo, &target),
        Command::Verify { repo, patch } => cmd_verify(&repo, &patch),
        Command::Recipes { action } => cmd_recipes(action, &store_path),
        Command::Ci { action } => cmd_ci(action),
        Command::Explain { run_id } => {
            tracing::info!(run_id, "explain stub: storage lookup lands in stage 1");
            Ok(())
        }
    }
}

fn build_registry() -> Registry {
    let mut r = Registry::new();
    r.register(Arc::new(RustAdapter::new()));
    r
}

fn cmd_scan(repo: &PathBuf, json: bool) -> Result<()> {
    let registry = build_registry();
    let adapter = registry.detect(repo).context("detect language")?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "repo": repo.display().to_string(),
                "language": adapter.name(),
                "candidates": [],
                "note": "candidate discovery lands in stage 1 (tree-sitter + bench-suite heuristic)"
            })
        );
    } else {
        println!("repo:      {}", repo.display());
        println!("language:  {}", adapter.name());
        println!("candidates: (stage 1) will enumerate hot primitives via tree-sitter + bench suite heuristic");
    }
    Ok(())
}

fn parse_target(raw: &str) -> Result<ods_core::TargetSig> {
    let parts: Vec<&str> = raw.split("::").collect();
    if parts.len() < 3 {
        anyhow::bail!(
            "expected `<lang>::<module>::<symbol>`, got `{raw}` (e.g. `rust::std::fs::read_dir`)"
        );
    }
    let language = parts[0].to_string();
    let symbol = parts[parts.len() - 1].to_string();
    let module = parts[1..parts.len() - 1].join("::");
    Ok(ods_core::TargetSig {
        language,
        module,
        symbol,
        arity: None,
    })
}

fn cmd_run(
    repo: &PathBuf,
    target_raw: &str,
    mode: RunMode,
    wall_cap_s: u64,
    spend_cap_usd: f64,
    store_path: &PathBuf,
) -> Result<()> {
    let target = parse_target(target_raw)?;
    let mode = match mode {
        RunMode::Dev => Mode::dev(),
        RunMode::Ci => Mode::Ci(ods_core::Budget {
            wall_cap: std::time::Duration::from_secs(wall_cap_s),
            spend_cap_usd,
        }),
    };
    let mut run = Run::new(mode);
    run.target = Some(target.clone());

    ensure_parent(store_path)?;
    let _store = Store::open(store_path)?;
    let registry = build_registry();
    let adapter = registry.detect(repo)?;

    tracing::info!(
        run_id = %run.id,
        target = %target,
        language = adapter.name(),
        stage = ?run.stage,
        "loop initialised; stage transitions land in stage 1"
    );

    while let Some(next) = run.advance()? {
        tracing::info!(stage = ?next, "transitioned");
    }
    println!("run {} completed (stub)", run.id);
    Ok(())
}

fn cmd_bench(repo: &PathBuf, target_raw: &str) -> Result<()> {
    let target = parse_target(target_raw)?;
    let registry = build_registry();
    let adapter = registry.detect(repo)?;
    let build = adapter.build(repo, None)?;
    let report = adapter.run_bench(&build, &target)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn cmd_verify(repo: &PathBuf, patch: &PathBuf) -> Result<()> {
    let registry = build_registry();
    let _adapter = registry.detect(repo)?;
    tracing::info!(
        patch = %patch.display(),
        "verify stub: zero-diff gate lands in stage 1"
    );
    Ok(())
}

fn cmd_recipes(action: RecipeAction, store_path: &PathBuf) -> Result<()> {
    ensure_parent(store_path)?;
    let store = Store::open(store_path)?;
    match action {
        RecipeAction::List { language } => {
            let hits = store.search(&RecipeQuery {
                language,
                category: None,
                min_promotion: Some(PromotionState::Seed),
                limit: Some(200),
            })?;
            if hits.is_empty() {
                println!("(no recipes. import seeds with `ods recipes import recipes/seed/<file>.yaml`)");
                return Ok(());
            }
            for r in hits {
                println!(
                    "{}\t{}\t{:?}\t{}\t{}",
                    r.id, r.language, r.promotion, r.category, r.name
                );
            }
        }
        RecipeAction::Show { id } => {
            let id = ods_recipes::RecipeId(id);
            match store.get(&id)? {
                Some(r) => println!("{}", serde_yaml::to_string(&r)?),
                None => anyhow::bail!("no such recipe: {id}"),
            }
        }
        RecipeAction::Import { path } => {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let recipe: ods_recipes::Recipe = serde_yaml::from_str(&text)
                .with_context(|| format!("parse {}", path.display()))?;
            store.upsert(&recipe)?;
            println!("imported {}", recipe.id);
        }
        RecipeAction::Export { out } => {
            let all = store.search(&RecipeQuery {
                limit: Some(10_000),
                ..Default::default()
            })?;
            let yaml = serde_yaml::to_string(&all)?;
            std::fs::write(&out, yaml)
                .with_context(|| format!("write {}", out.display()))?;
            println!("exported {} recipes to {}", all.len(), out.display());
        }
        RecipeAction::Promote { id, to } => {
            let id = ods_recipes::RecipeId(id);
            let mut recipe = store
                .get(&id)?
                .with_context(|| format!("no such recipe: {id}"))?;
            recipe.promotion = match to {
                RecipePromotion::Seed      => PromotionState::Seed,
                RecipePromotion::Candidate => PromotionState::Candidate,
                RecipePromotion::Validated => PromotionState::Validated,
                RecipePromotion::Corpus    => PromotionState::Corpus,
            };
            store.upsert(&recipe)?;
            println!("promoted {} to {:?}", recipe.id, recipe.promotion);
        }
    }
    Ok(())
}

fn cmd_ci(action: CiAction) -> Result<()> {
    match action {
        CiAction::Action { repo } => {
            tracing::info!(
                repo = %repo.display(),
                "ci action stub: Actions one-shot PR opening lands in stage 1"
            );
        }
        CiAction::Serve { port } => {
            tracing::info!(port, "ci serve stub: GitHub App webhook server lands in stage 2");
        }
    }
    Ok(())
}

fn ensure_parent(p: &PathBuf) -> Result<()> {
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent of {}", p.display()))?;
        }
    }
    Ok(())
}
