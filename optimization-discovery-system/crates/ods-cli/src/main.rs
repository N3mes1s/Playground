use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ods_agents::{Discoverer, Orchestrator};
use ods_ci::api::{b64_encode, GitHubClient};
use ods_ci::{AppCredentials, GitHubAppAuth, PrAllowlist};
use ods_core::{git::Worktree, Budget, Mode};
use ods_lang::Registry;
use ods_recipes::{
    score::score_recipes, PromotionState, RecipeQuery, Store,
};
use ods_report::{render_pr_body, ReportInputs};
use ods_verify::{GateInput, ZeroDiffGate};
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
        /// Print the per-event timeline (specialist turns, tool calls,
        /// reasoning blocks, verdicts) from the `.ods/runs.db` events table
        /// instead of the JSON artifact.
        #[arg(long)]
        timeline: bool,
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
        Command::Explain { repo, run_id, timeline } => cmd_explain(&repo, &run_id, timeline),
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
    let candidates = Discoverer::default().scan(repo)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "repo": repo.display().to_string(),
                "language": adapter.name(),
                "candidates": candidates,
            })
        );
    } else {
        println!("repo:      {}", repo.display());
        println!("language:  {}", adapter.name());
        if candidates.is_empty() {
            println!("candidates: (none discovered; run tree of this repo has no bench harnesses we recognise)");
        } else {
            println!("candidates ({} found):", candidates.len());
            println!("  score  language   module::symbol");
            for c in candidates.iter().take(20) {
                println!(
                    "  {:>5.2}  {:<9}  {}::{}    [{}:{}]",
                    c.score,
                    c.language,
                    c.module,
                    c.symbol,
                    c.source_file.display(),
                    c.source_line
                );
                if let Some(hint) = &c.naive_alt_hint {
                    println!("         hint: {}", hint);
                }
            }
        }
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
    let patch_text = std::fs::read_to_string(patch)
        .with_context(|| format!("read {}", patch.display()))?;

    let parent = repo.join(".ods").join("verify");
    let wt = Worktree::create(repo, "verify", &parent)?;

    // Apply the patch inside the worktree.
    let tmp = wt.path.join(".ods-verify.patch");
    std::fs::write(&tmp, patch_text.as_bytes())?;
    let apply = if wt.path.join(".git").exists() {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&wt.path)
            .args(["apply", "--whitespace=fix"])
            .arg(&tmp)
            .status()
    } else {
        std::process::Command::new("patch")
            .arg("-d")
            .arg(&wt.path)
            .args(["-p1", "-i"])
            .arg(&tmp)
            .status()
    };
    let _ = std::fs::remove_file(&tmp);
    let status = apply.with_context(|| "run patch/git apply")?;
    if !status.success() {
        anyhow::bail!("patch application failed (exit={:?})", status.code());
    }

    // Build + tests + fuzz, then feed the zero-diff gate.
    let build = adapter
        .build(&wt.path, None)
        .await
        .context("build after patch")?;
    let tests = adapter
        .run_tests(&build, ods_lang::TestScope::Full)
        .await
        .unwrap_or(ods_lang::TestReport {
            passed: 0,
            failed: 1,
            skipped: 0,
            log_path: None,
        });
    let target = ods_core::TargetSig {
        language: adapter.name().into(),
        module: "verify".into(),
        symbol: "target".into(),
        arity: None,
    };
    let fuzz = adapter
        .fuzz(&build, &target, std::time::Duration::from_secs(60))
        .await
        .ok();
    let input = GateInput {
        tests,
        property_tests: None,
        fuzz,
        semver: None,
        downstream_tests: vec![],
        touches_public_api: false,
        is_dep_bump: false,
    };
    let report = ZeroDiffGate::default().evaluate(&input)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
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
            let token = if let (Ok(app_id), Ok(pem), Ok(install)) = (
                std::env::var("ODS_APP_ID"),
                std::env::var("ODS_APP_PRIVATE_KEY_PEM"),
                std::env::var("ODS_APP_INSTALLATION_ID"),
            ) {
                let install_id: u64 = install
                    .parse()
                    .context("ODS_APP_INSTALLATION_ID must be numeric")?;
                let creds = AppCredentials {
                    app_id,
                    private_key_pem: pem,
                };
                let http = reqwest::Client::builder().build()?;
                GitHubAppAuth::installation_token(
                    &http,
                    "ods/0.1",
                    &creds,
                    install_id,
                )
                .await?
            } else {
                std::env::var("GITHUB_TOKEN")
                    .or_else(|_| std::env::var("ODS_GITHUB_TOKEN"))
                    .context(
                        "authenticate with either GITHUB_TOKEN/ODS_GITHUB_TOKEN or the \
                         ODS_APP_ID + ODS_APP_PRIVATE_KEY_PEM + ODS_APP_INSTALLATION_ID trio",
                    )?
            };
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
            // Rich PR body via ods-report.
            let recipes_applied_ids: Vec<ods_recipes::RecipeId> = art
                .recipes_applied
                .iter()
                .cloned()
                .map(ods_recipes::RecipeId)
                .collect();
            let pre_profile = art
                .pre_profile
                .clone()
                .unwrap_or(ods_lang::ProfileReport {
                    wall: std::time::Duration::ZERO,
                    cycles: None,
                    instructions: None,
                    llc_misses: None,
                    branch_misses: None,
                    syscall_counts: vec![],
                    alloc_count: None,
                    alloc_bytes: None,
                    flame_svg_path: None,
                });
            let post_profile = art
                .post_profile
                .clone()
                .unwrap_or_else(|| pre_profile.clone());
            let gate = art.gate.clone().unwrap_or(ods_verify::GateReport {
                decision: ods_verify::GateDecision::Pass,
                reasons: vec!["no gate output".into()],
            });
            let speedup = art.speedup.clone().unwrap_or(ods_measure::SpeedupVerdict {
                pre: ods_measure::ConfidenceInterval {
                    lower: 0.0,
                    point: 0.0,
                    upper: 0.0,
                    confidence: 0.99,
                },
                post: ods_measure::ConfidenceInterval {
                    lower: 0.0,
                    point: 0.0,
                    upper: 0.0,
                    confidence: 0.99,
                },
                speedup_point: 1.0,
                speedup_lower: 1.0,
                accepted: false,
                note: "no bench samples".into(),
            });
            let repro = format!(
                "ods run . --target {}::{}::{}",
                art.target.language, art.target.module, art.target.symbol
            );
            let body = render_pr_body(&ReportInputs {
                target: &art.target,
                recipes_applied: &recipes_applied_ids,
                speedup: &speedup,
                pre_profile: &pre_profile,
                post_profile: &post_profile,
                gate: &gate,
                reproduction_cmd: &repro,
            });
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

fn cmd_explain(repo: &PathBuf, run_id: &str, timeline: bool) -> Result<()> {
    if timeline {
        let runs_db = repo.join(".ods").join("runs.db");
        let store = ods_core::RunStore::open(&runs_db)
            .with_context(|| format!("open {}", runs_db.display()))?;
        let uuid = uuid::Uuid::parse_str(run_id)
            .with_context(|| format!("parse run id `{run_id}`"))?;
        let rid = ods_core::RunId(uuid);
        let events = store.events(&rid)?;
        if events.is_empty() {
            println!("(no events recorded for run {run_id})");
            return Ok(());
        }
        for ev in events {
            // Compact, human-friendly line per event. Detail is JSON; we
            // render key fields inline.
            let detail = ev.detail.unwrap_or_default();
            let summary = summarize_event(&ev.kind, &detail);
            println!("[{}] {:>4} {:<22} {:<16} {}", ev.at, ev.seq, ev.stage, ev.kind, summary);
        }
        return Ok(());
    }
    let path = repo.join(".ods").join("runs").join(format!("{run_id}.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    println!("{text}");
    Ok(())
}

fn summarize_event(kind: &str, detail_json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(detail_json) else {
        return String::new();
    };
    let field = |name: &str| -> String {
        v.get(name)
            .map(|x| match x {
                serde_json::Value::String(s) => s.clone(),
                _ => x.to_string(),
            })
            .unwrap_or_default()
    };
    match kind {
        "race-start" => format!("specialists={}", field("specialists")),
        "specialist-start" => format!(
            "{} target={} hyp={} seed={}",
            field("kind"),
            field("target"),
            field("hypothesis"),
            field("seed_recipe_id")
        ),
        "turn" => format!(
            "{} iter={} stop={} tok_in={} tok_out={}",
            field("specialist"),
            field("iteration"),
            field("stop_reason"),
            field("input_tokens"),
            field("output_tokens")
        ),
        "reasoning" => format!("{} iter={} >> {}", field("specialist"), field("iteration"), field("text_preview")),
        "tool-call" => format!(
            "{} iter={} {}({})",
            field("specialist"),
            field("iteration"),
            field("tool"),
            field("input_preview")
        ),
        "tool-result" => format!(
            "{} iter={} {} ok={} result={}",
            field("specialist"),
            field("iteration"),
            field("tool"),
            field("ok"),
            field("result_preview")
        ),
        "patch-proposed" => format!("{} diff_bytes={}", field("specialist"), field("diff_bytes")),
        "patch-rejected" => format!("{} reasons={}", field("specialist"), field("reasons")),
        "specialist-finish" => format!(
            "{} patch={} accepted={} cost=${} tok_in={} tok_out={}",
            field("kind"),
            field("patch_attempted"),
            field("accepted"),
            field("spent_usd"),
            field("tokens_in"),
            field("tokens_out")
        ),
        "race-finish" => format!(
            "winner={} cost=${} budget_exhausted={}",
            field("winner"),
            field("total_spent_usd"),
            field("budget_exhausted")
        ),
        _ => String::new(),
    }
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
