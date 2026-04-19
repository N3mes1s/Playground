use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ods_agents::Orchestrator;
use ods_ci::api::{b64_encode, GitHubClient};
use ods_ci::PrAllowlist;
use ods_core::{Budget, Mode};
use ods_lang::Registry;
use ods_recipes::{
    score::score_recipes, PromotionState, RecipeQuery, Store,
};
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
        #[arg(long, default_value_t = 900)]
        wall_cap_s: u64,
        #[arg(long, default_value_t = 5.0)]
        spend_cap_usd: f64,
        /// Allow the LLM transform path. Without this flag the orchestrator
        /// runs the measure+verify pipeline only, which is still useful as a
        /// baseline + determinism check.
        #[arg(long)]
        llm: bool,
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
        repo: PathBuf,
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
    Search {
        query: String,
        #[arg(long)]
        language: Option<String>,
        #[arg(long, default_value_t = 5)]
        limit: usize,
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
    /// GitHub Actions one-shot: run the loop, publish the patch as a PR via
    /// the GitHub REST API. Auth via `GITHUB_TOKEN` (fallback: `ODS_GITHUB_TOKEN`).
    Action {
        repo: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long, env = "ODS_GITHUB_REPO")]
        github_repo: String,
        #[arg(long, env = "ODS_PR_BASE")]
        base: Option<String>,
        #[arg(long, default_value = "ods/optimize")]
        branch_prefix: String,
        /// Comma-separated allowlist of `owner/repo` values. Empty = allow
        /// any. Required for server mode; optional for local action runs.
        #[arg(long, env = "ODS_ALLOWLIST")]
        allowlist: Option<String>,
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
        Command::Scan { repo, json } => cmd_scan(&repo, json).await,
        Command::Run { repo, target, mode, wall_cap_s, spend_cap_usd, llm } => {
            cmd_run(&repo, &target, mode, wall_cap_s, spend_cap_usd, llm, &store_path).await
        }
        Command::Bench { repo, target } => cmd_bench(&repo, &target).await,
        Command::Verify { repo, patch } => cmd_verify(&repo, &patch).await,
        Command::Recipes { action } => cmd_recipes(action, &store_path).await,
        Command::Ci { action } => cmd_ci(action, &store_path).await,
        Command::Explain { repo, run_id } => cmd_explain(&repo, &run_id),
    }
}

fn build_registry() -> Registry {
    let mut r = Registry::new();
    r.register(Arc::new(ods_lang_rust::RustAdapter::new()));
    r.register(Arc::new(ods_lang_go::GoAdapter::new()));
    r.register(Arc::new(ods_lang_ruby::RubyAdapter::new()));
    r.register(Arc::new(ods_lang_python::PythonAdapter::new()));
    r.register(Arc::new(ods_lang_c::CAdapter::new()));
    r.register(Arc::new(ods_lang_js::JsAdapter::new()));
    r.register(Arc::new(ods_lang_java::JavaAdapter::new()));
    r
}

async fn cmd_scan(repo: &PathBuf, json: bool) -> Result<()> {
    let registry = build_registry();
    let adapter = registry.detect(repo).await.context("detect language")?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "repo": repo.display().to_string(),
                "language": adapter.name(),
                "candidates": [],
                "note": "candidate discovery is heuristic today (tree-sitter + bench-suite scan lands next)"
            })
        );
    } else {
        println!("repo:      {}", repo.display());
        println!("language:  {}", adapter.name());
        println!("candidates: run `ods run {} --target <lang::mod::sym>` on a known hot primitive", repo.display());
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

async fn cmd_run(
    repo: &PathBuf,
    target_raw: &str,
    mode: RunMode,
    wall_cap_s: u64,
    spend_cap_usd: f64,
    allow_llm: bool,
    store_path: &PathBuf,
) -> Result<()> {
    let target = parse_target(target_raw)?;
    let mode = match mode {
        RunMode::Dev => Mode::Dev,
        RunMode::Ci => Mode::Ci(Budget {
            wall_cap: std::time::Duration::from_secs(wall_cap_s),
            spend_cap_usd,
        }),
    };

    ensure_parent(store_path)?;
    let store = Arc::new(Store::open(store_path)?);
    let registry = build_registry();
    let adapter = registry.detect(repo).await?;

    let orch = Orchestrator::new(adapter, store, repo.clone(), mode);
    let art = orch.run(target, allow_llm).await?;
    println!("run {} completed", art.run_id);
    println!("artifact: {}/.ods/runs/{}.json", repo.display(), art.run_id);
    if let Some(gate) = &art.gate {
        println!("zero-diff gate: {:?}", gate.decision);
    }
    if let Some(v) = &art.speedup {
        println!(
            "speedup: {:.2}x (lower {:.2}x, accepted: {})",
            v.speedup_point, v.speedup_lower, v.accepted
        );
    }
    Ok(())
}

async fn cmd_bench(repo: &PathBuf, target_raw: &str) -> Result<()> {
    let target = parse_target(target_raw)?;
    let registry = build_registry();
    let adapter = registry.detect(repo).await?;
    let build = adapter.build(repo, None).await?;
    let report = adapter.run_bench(&build, &target).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn cmd_verify(repo: &PathBuf, patch: &PathBuf) -> Result<()> {
    let registry = build_registry();
    let adapter = registry.detect(repo).await?;
    tracing::info!(
        patch = %patch.display(),
        lang = adapter.name(),
        "verify stub: apply the patch in a worktree and run the zero-diff gate"
    );
    Ok(())
}

async fn cmd_recipes(action: RecipeAction, store_path: &PathBuf) -> Result<()> {
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
        RecipeAction::Search { query, language, limit } => {
            let candidates = store.search(&RecipeQuery {
                language,
                category: None,
                min_promotion: Some(PromotionState::Seed),
                limit: Some(1000),
            })?;
            let ranked = score_recipes(&candidates, &query);
            for r in ranked.into_iter().take(limit) {
                println!(
                    "{:>6.3}  {}  [{}]  {}",
                    r.score, r.recipe.id, r.recipe.category, r.recipe.name
                );
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

async fn cmd_ci(action: CiAction, store_path: &PathBuf) -> Result<()> {
    match action {
        CiAction::Action {
            repo,
            target,
            github_repo,
            base,
            branch_prefix,
            allowlist,
        } => {
            if let Some(list) = allowlist {
                let al = PrAllowlist::from_list(
                    list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                );
                if !al.permits(&github_repo) {
                    anyhow::bail!("{github_repo} not on ODS_ALLOWLIST");
                }
            }
            ensure_parent(store_path)?;
            let store = Arc::new(Store::open(store_path)?);
            let registry = build_registry();
            let adapter = registry.detect(&repo).await?;
            let orch = Orchestrator::new(adapter, store, repo.clone(), Mode::ci_default());
            let target = parse_target(&target)?;
            let art = orch.run(target, false).await?;

            let (owner, repo_name) = split_repo(&github_repo)?;
            let token = std::env::var("GITHUB_TOKEN")
                .or_else(|_| std::env::var("ODS_GITHUB_TOKEN"))
                .context("GITHUB_TOKEN / ODS_GITHUB_TOKEN must be set")?;
            let gh = GitHubClient::new(token)?;

            let base_branch = if let Some(b) = base {
                b
            } else {
                gh.default_branch(&owner, &repo_name).await?
            };
            let base_sha = gh.branch_sha(&owner, &repo_name, &base_branch).await?;
            let head_branch = format!("{branch_prefix}/{}", art.run_id);
            gh.create_branch(&owner, &repo_name, &head_branch, &base_sha)
                .await?;

            // Minimal PR body: attach the JSON artifact under docs/ods/runs/.
            let artifact_body = serde_json::to_string_pretty(&art)?;
            let artifact_b64 = b64_encode(artifact_body.as_bytes());
            gh.put_file(
                &owner,
                &repo_name,
                &head_branch,
                &format!("docs/ods/runs/{}.json", art.run_id),
                &artifact_b64,
                &format!("ods: publish run {}", art.run_id),
            )
            .await?;

            let title = format!(
                "ods: measurement report for {}::{}::{}",
                art.target.language, art.target.module, art.target.symbol
            );
            let body = format!(
                "This PR carries an automated measurement run. Artifact at `docs/ods/runs/{}.json`.\n\n\
                 - stages completed: {:?}\n- recipes applied: {:?}\n- zero-diff gate: {:?}\n",
                art.run_id, art.stages_completed, art.recipes_applied, art.gate
            );
            let pr = gh
                .open_pr(
                    &owner,
                    &repo_name,
                    &head_branch,
                    &base_branch,
                    &title,
                    &body,
                    true,
                )
                .await?;
            println!("{}", pr.html_url);
        }
        CiAction::Serve { port } => {
            use ods_ci::webhook::WebhookServer;
            let (_tx, rx) = tokio::sync::watch::channel(false);
            let server = WebhookServer::new(port);
            let mut events = server.run(rx).await?;
            while let Some(e) = events.recv().await {
                tracing::info!(?e, "webhook event received");
            }
        }
    }
    Ok(())
}

fn cmd_explain(repo: &PathBuf, run_id: &str) -> Result<()> {
    let path = repo.join(".ods").join("runs").join(format!("{run_id}.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    println!("{text}");
    Ok(())
}

fn split_repo(full: &str) -> Result<(String, String)> {
    let mut parts = full.splitn(2, '/');
    let owner = parts.next().context("missing owner")?;
    let repo = parts.next().context("missing repo")?;
    if owner.is_empty() || repo.is_empty() {
        anyhow::bail!("expected owner/repo, got `{full}`");
    }
    Ok((owner.to_string(), repo.to_string()))
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
