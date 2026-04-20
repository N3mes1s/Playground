//! End-to-end run orchestrator. Walks `TargetSelect -> ... -> Harvest` using
//! the configured [`LanguageAdapter`], [`Planner`], specialists, and recipe
//! store.
//!
//! Persistence: the primary source of truth is the SQLite [`RunStore`] under
//! `<repo>/.ods/runs.db`. A mirror JSON dump at `.ods/runs/<run_id>.json`
//! keeps the "one file per run" story for `ods explain` and CI artifact
//! upload.
//!
//! When `allow_llm == true` and `ANTHROPIC_API_KEY` is set, the Transform
//! stage spawns specialists in parallel worktrees via [`crate::race`] and
//! applies the winner's patch. Otherwise we run the measure+verify pipeline
//! against the unchanged checkout - still useful as a baseline + determinism
//! check.

use crate::harvest;
use crate::observe::{EventSink, SqliteEventSink};
use crate::planner::Planner;
use crate::race::{self, RaceInput};
use anyhow::{Context, Result};
use ods_core::{
    domain::{Hypothesis, OptimizationCategory, TargetSig},
    loop_::LoopStage,
    Mode, Run, RunRecord, RunStatus, RunStore,
};
use ods_lang::{BenchReport, LanguageAdapter, ProfileReport, TestReport, TestScope};
use ods_measure::{compare, EnvFingerprint, RerunReport, Sample, SpeedupVerdict};
use ods_recipes::{RecipeId, Store};
use ods_verify::{GateInput, GateReport, ZeroDiffGate};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunArtifact {
    pub run_id: String,
    pub language: String,
    pub target: TargetSig,
    pub hypotheses: Vec<Hypothesis>,
    pub stages_completed: Vec<LoopStage>,
    pub pre_profile: Option<ProfileReport>,
    pub post_profile: Option<ProfileReport>,
    pub pre_bench: Option<BenchReport>,
    pub post_bench: Option<BenchReport>,
    pub speedup: Option<SpeedupVerdict>,
    pub tests: Option<TestReport>,
    pub gate: Option<GateReport>,
    pub recipes_applied: Vec<String>,
    pub patch_diff: Option<String>,
    pub winning_specialist: Option<String>,
    pub harvested_recipe: Option<String>,
    /// ID of the LLM-generalized (Phase 2 of harvest) recipe, if the
    /// Generalizer ran and produced a parseable pattern. This is the
    /// recipe that carries cross-repo reusability — while
    /// `harvested_recipe` is repo-specific provenance.
    #[serde(default)]
    pub generalized_recipe: Option<String>,
    pub env_fingerprint: EnvFingerprint,
    pub determinism: Option<RerunReport>,
    pub pr_withheld: bool,
    pub spent_usd: f64,
    pub note: Option<String>,
    /// When we scaffolded a synthetic bench harness (because the repo
    /// didn't ship one), this is populated. The PR body calls this out so
    /// reviewers know to keep the added file as a lasting improvement.
    pub scaffolded_bench: Option<ScaffoldSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldSummary {
    pub bench_name: String,
    pub bench_file: String,
    pub created_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub added_criterion_dep: bool,
}

pub struct Orchestrator {
    pub adapter: Arc<dyn LanguageAdapter>,
    pub store: Arc<Store>,
    pub repo: PathBuf,
    pub mode: Mode,
}

impl Orchestrator {
    pub fn new(
        adapter: Arc<dyn LanguageAdapter>,
        store: Arc<Store>,
        repo: PathBuf,
        mode: Mode,
    ) -> Self {
        Self {
            adapter,
            store,
            repo,
            mode,
        }
    }

    pub async fn run(&self, target: TargetSig, allow_llm: bool) -> Result<RunArtifact> {
        let mut run = Run::new(self.mode.clone());
        run.target = Some(target.clone());
        let run_id = run.id;
        let started_at = now_rfc3339()?;

        let fingerprint = EnvFingerprint::capture();
        let mut artifact = RunArtifact {
            run_id: run_id.to_string(),
            language: self.adapter.name().into(),
            target: target.clone(),
            hypotheses: vec![],
            stages_completed: vec![],
            pre_profile: None,
            post_profile: None,
            pre_bench: None,
            post_bench: None,
            speedup: None,
            tests: None,
            gate: None,
            recipes_applied: vec![],
            patch_diff: None,
            winning_specialist: None,
            harvested_recipe: None,
            generalized_recipe: None,
            env_fingerprint: fingerprint.clone(),
            determinism: None,
            pr_withheld: false,
            spent_usd: 0.0,
            note: None,
            scaffolded_bench: None,
        };

        // RunStore --------------------------------------------------------
        let runs_db = self.repo.join(".ods").join("runs.db");
        if let Some(parent) = runs_db.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let run_store = RunStore::open(&runs_db).context("open run store")?;
        // Build the observability sink on top of a second handle to the same
        // SQLite file so per-event writes don't contend with the stage-level
        // writer. SQLite with bundled features serialises writes.
        let sink_store = RunStore::open(&runs_db).context("open sink store")?;
        let sink: Arc<dyn EventSink> =
            Arc::new(SqliteEventSink::shared(Arc::new(Mutex::new(sink_store))));
        run_store.insert(&RunRecord {
            id: run_id.to_string(),
            language: self.adapter.name().into(),
            target: (
                target.language.clone(),
                target.module.clone(),
                target.symbol.clone(),
            ),
            stage: LoopStage::TargetSelect,
            spent_usd: 0.0,
            started_at: started_at.clone(),
            updated_at: started_at.clone(),
            finished_at: None,
            status: RunStatus::InProgress,
            artifact_json: serde_json::to_string(&artifact)?,
        })?;
        run_store.append_event(&run_id, LoopStage::TargetSelect, "start", None)?;

        // TargetSelect (done by caller) ----------------------------------
        artifact.stages_completed.push(LoopStage::TargetSelect);
        run.advance()?;

        // Profile (pre) --------------------------------------------------
        let build = self
            .adapter
            .build(&self.repo, None)
            .await
            .context("adapter.build")?;
        let pre_profile = self.adapter.profile(&build, &target).await.ok();
        artifact.pre_profile = pre_profile.clone();
        let mut pre_bench = self.adapter.run_bench(&build, &target).await.ok();
        // If the target crate has no bench harness, scaffold one so we can
        // still produce structured pre/post samples. We only do this for
        // the Rust adapter today; other languages will grow analogous
        // scaffolders in stage-6.
        let bench_empty = pre_bench
            .as_ref()
            .map(|b| b.samples.is_empty())
            .unwrap_or(true);
        if self.adapter.name() == "rust" && bench_empty {
            match ods_lang_rust::bench_scaffold::scaffold(&self.repo, &target) {
                Ok(outcome) => {
                    artifact.scaffolded_bench = Some(ScaffoldSummary {
                        bench_name: outcome.bench_name.clone(),
                        bench_file: outcome.bench_file.display().to_string(),
                        created_files: outcome
                            .created_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect(),
                        modified_files: outcome
                            .modified_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect(),
                        added_criterion_dep: outcome.added_criterion_dep,
                    });
                    tracing::info!(
                        bench = %outcome.bench_name,
                        "scaffolded synthetic bench; re-running pre-bench"
                    );
                    let build2 = self
                        .adapter
                        .build(&self.repo, None)
                        .await
                        .unwrap_or(build.clone());
                    pre_bench = self.adapter.run_bench(&build2, &target).await.ok();
                    artifact.pre_bench = pre_bench.clone();
                }
                Err(e) => {
                    tracing::warn!(err = %e, "bench scaffold failed; continuing without");
                }
            }
        } else if self.adapter.name() == "ruby" && bench_empty {
            // Mirror of the Rust path. Bootsnap and most Ruby gems
            // don't ship `benchmark/` so without this the run hits
            // the bench stage with empty samples and the gate rejects
            // every patch on lack of evidence.
            match ods_lang_ruby::bench_scaffold::scaffold(&self.repo, &target) {
                Ok(outcome) => {
                    artifact.scaffolded_bench = Some(ScaffoldSummary {
                        bench_name: outcome.bench_name.clone(),
                        bench_file: outcome.bench_file.display().to_string(),
                        created_files: outcome
                            .created_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect(),
                        modified_files: outcome
                            .modified_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect(),
                        // The Ruby scaffolder reports `benchmark-ips`
                        // additions; we reuse the Rust-named field
                        // here since the artifact shape is shared
                        // and "added_criterion_dep" reads as
                        // "added a bench dep" in the PR body.
                        added_criterion_dep: outcome.added_benchmark_ips_dep,
                    });
                    tracing::info!(
                        bench = %outcome.bench_name,
                        "scaffolded ruby benchmark-ips harness; re-running pre-bench"
                    );
                    let build2 = self
                        .adapter
                        .build(&self.repo, None)
                        .await
                        .unwrap_or(build.clone());
                    pre_bench = self.adapter.run_bench(&build2, &target).await.ok();
                    artifact.pre_bench = pre_bench.clone();
                }
                Err(e) => {
                    tracing::warn!(err = %e, "ruby bench scaffold failed; continuing without");
                }
            }
        } else {
            artifact.pre_bench = pre_bench.clone();
        }
        artifact.stages_completed.push(LoopStage::Profile);
        persist(&run_store, &run_id, LoopStage::Profile, &artifact)?;
        run.advance()?;

        // RecipeRetrieve -------------------------------------------------
        //
        // Before querying the corpus, run the Explorer in read-only mode
        // against this repo so recipes proposed FROM this codebase enter
        // the planner's retrieval pool for THIS run. Every successful
        // Explorer proposal lands as `Hypothesized` in the shared store;
        // next run's discover pass picks them up too, and the harvester
        // (Flywheel #1) can later promote them. This is how the corpus
        // grows from the codebases the product sees rather than just
        // from hand-authored seeds.
        //
        // Capped at $0.75 so a normal 3-specialist race at $5 still has
        // >80% of budget left for patches. Explorer is skipped when
        // `ANTHROPIC_API_KEY` is absent (same gate as the race below).
        if allow_llm && std::env::var("ANTHROPIC_API_KEY").is_ok() {
            let explorer_cap = 0.75_f64.min(
                self.mode
                    .budget()
                    .map(|b| b.spend_cap_usd * 0.15)
                    .unwrap_or(0.75),
            );
            let tracker = ods_core::BudgetTracker::new(Some(&ods_core::Budget {
                wall_cap: std::time::Duration::from_secs(180),
                spend_cap_usd: explorer_cap,
            }));
            let input = crate::explorer::ExplorerInput {
                repo: &self.repo,
                language: self.adapter.name().to_string(),
                max_recipes: 5,
                max_iters: 10,
                budget_tracker: Some(tracker),
            };
            match crate::explorer::run_explorer(input).await {
                Ok(outcome) => {
                    let mut added = 0usize;
                    let mut rejected = 0usize;
                    for r in &outcome.proposed_recipes {
                        if self.store.get(&r.id).ok().flatten().is_some() {
                            continue; // already in corpus from a prior run
                        }
                        // Two-stage validation gate:
                        //   1. The pattern must compile against the
                        //      language's tree-sitter grammar.
                        //   2. The pattern must match ≥1 file in the
                        //      repo the Explorer just surveyed. A
                        //      proposal that doesn't fire on its OWN
                        //      source material is LLM-hallucinated; it
                        //      would waste Discoverer cycles forever.
                        // Both checks reject at the write boundary so
                        // the store only holds patterns we've proven
                        // are grammar-valid AND empirically grounded.
                        if let Err(e) = crate::recipe_validate::validate_pattern_compiles(
                            &r.language,
                            &r.trigger.ast_pattern,
                        ) {
                            rejected += 1;
                            crate::observe::emit(
                                Some(&sink),
                                &run_id,
                                LoopStage::RecipeRetrieve,
                                crate::observe::AgentEvent::RecipeRejected {
                                    source: "explorer".into(),
                                    recipe_id: r.id.0.clone(),
                                    reason: format!("compile: {e:#}"),
                                },
                            );
                            continue;
                        }
                        if !pattern_matches_any_repo_file(
                            &self.repo,
                            &r.language,
                            &r.trigger.ast_pattern,
                        ) {
                            rejected += 1;
                            crate::observe::emit(
                                Some(&sink),
                                &run_id,
                                LoopStage::RecipeRetrieve,
                                crate::observe::AgentEvent::RecipeRejected {
                                    source: "explorer".into(),
                                    recipe_id: r.id.0.clone(),
                                    reason: "compiled but matched no file in the surveyed repo"
                                        .into(),
                                },
                            );
                            continue;
                        }
                        if self.store.upsert(r).is_ok() {
                            added += 1;
                        }
                    }
                    tracing::info!(
                        proposed = outcome.proposed_recipes.len(),
                        added,
                        rejected,
                        cost_usd = outcome.spent_usd,
                        "explorer survey complete; hypothesized recipes added to corpus"
                    );
                }
                Err(e) => {
                    tracing::warn!(err = %e, "explorer survey failed; continuing with corpus as-is");
                }
            }
        }

        let categories = infer_categories(pre_profile.as_ref());
        let planner = Planner::new(&self.store);
        let plan = planner.plan(&target, &categories).unwrap_or_default();
        artifact.hypotheses = plan.iter().map(|(_, h)| h.clone()).collect();
        artifact.recipes_applied = plan
            .iter()
            .filter_map(|(_, h)| h.seed_recipe_id.clone())
            .collect();
        artifact.stages_completed.push(LoopStage::RecipeRetrieve);
        persist(&run_store, &run_id, LoopStage::RecipeRetrieve, &artifact)?;
        run.advance()?;
        artifact.stages_completed.push(LoopStage::Hypothesize);
        run.advance()?;

        // Transform (LLM race optional) ----------------------------------
        let mut winner_diff: Option<String> = None;
        let mut winner_kind: Option<String> = None;
        let mut post_bench_override: Option<BenchReport> = None;
        let mut speedup_override: Option<SpeedupVerdict> = None;
        let mut winner_worktree: Option<PathBuf> = None;
        // Winner's WorktreeHandle kept alive for the duration of the
        // bench + rerun-N determinism gate. Dropped when orchestrator
        // returns so cleanup still happens.
        let mut _winner_handle: Option<ods_core::WorktreeHandle> = None;
        if allow_llm && std::env::var("ANTHROPIC_API_KEY").is_ok() {
            // One shared tracker per run. Its Instant-based wall clock
            // starts here so the full LLM race shares the same wall budget
            // with any future parallel work (e.g. Explorer specialists).
            let budget_tracker = self.mode.budget_tracker();
            let input = RaceInput {
                repo: &self.repo,
                target: &target,
                adapter: self.adapter.clone(),
                plan: plan.clone(),
                mode: self.mode.clone(),
                pre_bench: pre_bench.clone(),
                pre_profile: pre_profile.clone(),
                recipe_snippets: collect_snippets(&self.store, &artifact.recipes_applied),
                // Worktrees must live OUTSIDE the source repo; otherwise the
                // copy-based fallback recurses into the worktree dir it is
                // currently writing to (File name too long, os error 36).
                worktree_parent: std::env::temp_dir()
                    .join("ods-worktrees")
                    .join(run_id.to_string()),
                fuzz_budget: Duration::from_secs(60),
                sink: Some(sink.clone()),
                run_id,
                budget_tracker: Some(budget_tracker),
            };
            match race::run_specialists(input).await {
                Ok(out) => {
                    artifact.spent_usd = out.spent_usd;
                    run.spent_usd = out.spent_usd;
                    if out.budget_exhausted {
                        artifact.pr_withheld = true;
                        artifact.note = Some(format!(
                            "budget exhausted after ${:.2}; PR withheld",
                            out.spent_usd
                        ));
                    }
                    // Persist counter-evidence on retrieved recipes that
                    // failed to help here. This is what makes the corpus
                    // self-curating over time.
                    for (recipe_id, outcome) in &out.negative_records {
                        let _ = crate::harvest::record_negatives(
                            std::slice::from_ref(recipe_id),
                            &self.repo.display().to_string(),
                            &target,
                            *outcome,
                            self.store.as_ref(),
                        );
                    }
                    if let Some(w) = out.winner {
                        winner_diff = Some(w.patch.unified_diff.clone());
                        winner_kind = Some(format!("{:?}", w.outcome.kind));
                        post_bench_override = Some(w.post_bench.clone());
                        speedup_override = Some(w.verdict.clone());
                        winner_worktree = Some(w.worktree_path.clone());

                        // Auto-harvest the winning transform. Phase 1 writes
                        // a specific per-target Candidate (provenance). Phase 2
                        // calls the LLM Generalizer to turn the specific win
                        // into a reusable, repo-agnostic Hypothesized recipe.
                        // This is the flywheel: every successful run grows
                        // the corpus with a cross-repo-transferable pattern,
                        // not just a one-liner log entry.
                        let commit_sha =
                            current_commit(&self.repo).unwrap_or_else(|| "HEAD".into());
                        let repo_full = self.repo.display().to_string();
                        let generalizer_client = std::env::var("ANTHROPIC_API_KEY")
                            .ok()
                            .and_then(|k| crate::anthropic::AnthropicClient::new(k).ok());
                        match harvest::harvest_full(
                            &w,
                            &target,
                            &repo_full,
                            &commit_sha,
                            self.store.as_ref(),
                            generalizer_client.as_ref(),
                        ) {
                            Ok(harvest::HarvestOutcome {
                                specific_id,
                                generalized_id,
                            }) => {
                                artifact.harvested_recipe = Some(specific_id.0.clone());
                                artifact.generalized_recipe = generalized_id.map(|g| g.0.clone());
                            }
                            Err(e) => {
                                tracing::warn!(err = %e, "harvest failed; continuing without");
                            }
                        }

                        // Preserve the worktree alive past the race so the
                        // determinism rerun gate below can actually
                        // re-measure against the patched build. Done last so
                        // harvest_full can still read `&w`.
                        _winner_handle = Some(w._handle);
                    }
                }
                Err(e) => {
                    artifact.note = Some(format!("race failed: {e}"));
                }
            }
        } else if allow_llm {
            artifact.note =
                Some("allow_llm requested but ANTHROPIC_API_KEY not set; skipping LLM race".into());
        }
        artifact.patch_diff = winner_diff;
        artifact.winning_specialist = winner_kind.clone();
        artifact.stages_completed.push(LoopStage::Transform);
        persist(&run_store, &run_id, LoopStage::Transform, &artifact)?;
        run.advance()?;

        // Verify ---------------------------------------------------------
        let tests = self
            .adapter
            .run_tests(&build, TestScope::Full)
            .await
            .unwrap_or(TestReport {
                passed: 0,
                failed: 0,
                skipped: 0,
                log_path: None,
            });
        artifact.tests = Some(tests.clone());
        let gate = ZeroDiffGate::default().evaluate(&GateInput {
            tests,
            property_tests: None,
            fuzz: None,
            semver: None,
            downstream_tests: vec![],
            touches_public_api: false,
            is_dep_bump: false,
        })?;
        artifact.gate = Some(gate);
        artifact.stages_completed.push(LoopStage::Verify);
        persist(&run_store, &run_id, LoopStage::Verify, &artifact)?;
        run.advance()?;

        // Bench (post + rerun-N) -----------------------------------------
        //
        // We only re-measure post-bench when a specialist actually won the
        // race AND produced a post_bench_override sourced from the patched
        // worktree. Without a winner, the main repo is unchanged and
        // re-running the bench here just measures the pre-bench a second
        // time; any "speedup" reported would be pure variance (we observed
        // a ~1.41x noise reading in one dogfood against a no-op scaffolded
        // bench). Reporting that would be a lie.
        let had_winner = winner_kind.is_some();
        let post_bench = if had_winner {
            if let Some(b) = post_bench_override {
                Some(b)
            } else {
                self.adapter.run_bench(&build, &target).await.ok()
            }
        } else {
            None
        };
        artifact.post_bench = post_bench.clone();
        let verdict = if had_winner {
            if let Some(v) = speedup_override {
                Some(v)
            } else {
                single_sample_verdict(pre_bench.as_ref(), post_bench.as_ref())
            }
        } else {
            None
        };
        artifact.speedup = verdict.clone();

        // Determinism gate: re-measure pre+post N times and require CI
        // overlap + stable env fingerprint before accepting the speedup.
        //
        // The previous implementation stuffed `vec![pre_ns; 30]` into
        // each closure — trivially deterministic by construction and
        // told us nothing about actual measurement noise. The real
        // gate below re-runs the bench against the original
        // `build` (pristine pre) and a Build rebuilt from the
        // winner's still-alive worktree (patched post) once per
        // iteration.
        //
        // Cost: ~3× bench wall-time. Runs only when a winner exists,
        // the winner's worktree is still alive (we held _winner_handle),
        // and a non-empty pre_bench was captured.
        if had_winner && winner_worktree.is_some() && pre_bench.is_some() {
            let wt_path = winner_worktree.as_ref().expect("checked").clone();
            // Re-use the pristine `build` from pre-profile for the pre
            // side; build the winner's worktree once here so we don't
            // pay a rebuild cost per iteration.
            let post_build = match self.adapter.build(&wt_path, None).await {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::warn!(err = %e, "rerun: rebuilding winner worktree failed; skipping determinism gate");
                    None
                }
            };

            if let Some(post_build) = post_build {
                const N: u32 = 3;
                let fingerprint = EnvFingerprint::capture();
                let mut verdicts: Vec<SpeedupVerdict> = Vec::with_capacity(N as usize);
                let mut fingerprint_stable = true;
                for i in 0..N {
                    let fp_now = EnvFingerprint::capture();
                    if !fp_now.diff(&fingerprint).is_empty() {
                        fingerprint_stable = false;
                    }
                    let pre_bench_i = match self.adapter.run_bench(&build, &target).await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                iter = i,
                                err = %e,
                                "rerun: pre bench failed"
                            );
                            continue;
                        }
                    };
                    let post_bench_i = match self.adapter.run_bench(&post_build, &target).await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                iter = i,
                                err = %e,
                                "rerun: post bench failed"
                            );
                            continue;
                        }
                    };
                    let (Some(pp), Some(qq)) =
                        (pre_bench_i.samples.first(), post_bench_i.samples.first())
                    else {
                        continue;
                    };
                    let pre_sample = Sample {
                        name: "pre".into(),
                        values_ns: vec![pp.ns_per_iter],
                    };
                    let post_sample = Sample {
                        name: "post".into(),
                        values_ns: vec![qq.ns_per_iter],
                    };
                    verdicts.push(compare(&pre_sample, &post_sample));
                }
                let all_accepted = !verdicts.is_empty() && verdicts.iter().all(|v| v.accepted);
                let cis_overlap = cis_overlap(&verdicts);
                let r = RerunReport {
                    n: N,
                    verdicts,
                    fingerprint,
                    fingerprint_stable,
                    all_accepted,
                    cis_overlap,
                };
                if !(r.cis_overlap && r.fingerprint_stable && r.all_accepted) {
                    artifact.pr_withheld = true;
                    artifact.note = Some(
                        "determinism gate failed (CI overlap, fingerprint drift, or non-accepted rerun)"
                            .into(),
                    );
                }
                artifact.determinism = Some(r);
            }
        }
        artifact.stages_completed.push(LoopStage::Bench);
        persist(&run_store, &run_id, LoopStage::Bench, &artifact)?;
        run.advance()?;

        // Explain + Harvest ---------------------------------------------
        artifact.stages_completed.push(LoopStage::Explain);
        artifact.stages_completed.push(LoopStage::Harvest);

        persist_json(&self.repo, &artifact)?;
        run_store.finish(
            &run_id,
            RunStatus::Completed,
            &serde_json::to_string(&artifact)?,
        )?;
        Ok(artifact)
    }
}

fn infer_categories(profile: Option<&ProfileReport>) -> Vec<OptimizationCategory> {
    if let Some(p) = profile {
        if !p.syscall_counts.is_empty() {
            return vec![
                OptimizationCategory::SyscallElimination,
                OptimizationCategory::AllocReduction,
                OptimizationCategory::FastPathSpecialization,
            ];
        }
    }
    OptimizationCategory::ALL.to_vec()
}

fn collect_snippets(store: &Store, ids: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in ids {
        if let Ok(Some(r)) = store.get(&RecipeId(id.clone())) {
            out.push(format!("{}: {}", r.id, r.transformation.steps.join(" | ")));
        }
    }
    out
}

fn current_commit(repo: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn single_sample_verdict(
    pre: Option<&BenchReport>,
    post: Option<&BenchReport>,
) -> Option<SpeedupVerdict> {
    match (pre, post) {
        (Some(a), Some(b)) => match (a.samples.first(), b.samples.first()) {
            (Some(p), Some(q)) => {
                let pre_s = Sample {
                    name: "pre".into(),
                    values_ns: vec![p.ns_per_iter; 30],
                };
                let post_s = Sample {
                    name: "post".into(),
                    values_ns: vec![q.ns_per_iter; 30],
                };
                Some(compare(&pre_s, &post_s))
            }
            _ => None,
        },
        _ => None,
    }
}

fn persist(
    run_store: &RunStore,
    id: &ods_core::RunId,
    stage: LoopStage,
    artifact: &RunArtifact,
) -> Result<()> {
    run_store.update_stage(
        id,
        stage,
        artifact.spent_usd,
        &serde_json::to_string(artifact)?,
    )?;
    run_store.append_event(id, stage, "done", None)?;
    Ok(())
}

fn persist_json(repo: &PathBuf, art: &RunArtifact) -> Result<()> {
    let dir = repo.join(".ods").join("runs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", art.run_id));
    let body = serde_json::to_string_pretty(art)?;
    std::fs::write(&path, body)?;
    Ok(())
}

fn now_rfc3339() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

/// Every pair of post-CIs must overlap for the rerun gate to accept.
/// Local helper because `ods_measure::rerun::cis_overlap` is
/// module-private — we run the rerun loop inline against real benches
/// here instead of going through the helper.
fn cis_overlap(verdicts: &[SpeedupVerdict]) -> bool {
    for i in 0..verdicts.len() {
        for j in (i + 1)..verdicts.len() {
            let a = &verdicts[i].post;
            let b = &verdicts[j].post;
            let lo = a.lower.max(b.lower);
            let hi = a.upper.min(b.upper);
            if lo > hi {
                return false;
            }
        }
    }
    !verdicts.is_empty()
}

/// Walk `repo` for source files matching `language` and return true as
/// soon as `pattern` produces ≥1 tree-sitter match in any of them.
///
/// Used as the stricter second stage of the Explorer validation gate:
/// a pattern that compiles but doesn't fire on the repo the Explorer
/// just surveyed is almost certainly a hallucination; accepting it
/// would waste Discoverer cycles forever. Short-circuits on the first
/// hit so typical success cost is bounded by a couple of file reads.
fn pattern_matches_any_repo_file(
    repo: &std::path::Path,
    language: &str,
    pattern: &str,
) -> bool {
    let ext: &[&str] = match language {
        "rust" => &["rs"],
        "python" => &["py"],
        "go" => &["go"],
        "ruby" => &["rb"],
        _ => return false,
    };
    for entry in walkdir::WalkDir::new(repo)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        // Skip vendored/generated trees that blow up walk cost and
        // aren't representative of the repo's code under optimization.
        if path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("target" | "node_modules" | ".git" | "vendor" | "dist" | "build")
            )
        }) {
            continue;
        }
        let Some(file_ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if !ext.contains(&file_ext) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if matches!(
            crate::recipe_validate::validate_pattern_matches_source(language, pattern, &text),
            Ok(true)
        ) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ods_lang::{AstMatch, BenchSample, Build, Edit, FuzzReport, Patch};
    use std::path::Path;

    struct NoopAdapter;

    #[async_trait]
    impl LanguageAdapter for NoopAdapter {
        fn name(&self) -> &'static str {
            "noop"
        }
        async fn detect(&self, _: &Path) -> Result<bool> {
            Ok(true)
        }
        async fn build(&self, p: &Path, _: Option<&Patch>) -> Result<Build> {
            Ok(Build {
                workdir: p.to_path_buf(),
                artifact: None,
                toolchain: "noop".into(),
            })
        }
        async fn run_tests(&self, _: &Build, _: TestScope) -> Result<TestReport> {
            Ok(TestReport {
                passed: 10,
                failed: 0,
                skipped: 0,
                log_path: None,
            })
        }
        async fn run_bench(&self, _: &Build, _: &TargetSig) -> Result<BenchReport> {
            Ok(BenchReport {
                samples: vec![BenchSample {
                    name: "x".into(),
                    ns_per_iter: 100.0,
                    iters: 1,
                }],
            })
        }
        async fn profile(&self, _: &Build, _: &TargetSig) -> Result<ProfileReport> {
            Ok(ProfileReport {
                wall: Duration::ZERO,
                cycles: None,
                instructions: None,
                llc_misses: None,
                branch_misses: None,
                syscall_counts: vec![("read".into(), 1)],
                alloc_count: None,
                alloc_bytes: None,
                flame_svg_path: None,
            })
        }
        async fn ast_query(&self, _: &Path, _: &str) -> Result<Vec<AstMatch>> {
            Ok(vec![])
        }
        fn emit_patch(&self, edits: &[Edit]) -> Result<Patch> {
            Ok(Patch {
                unified_diff: String::new(),
                edits: edits.to_vec(),
            })
        }
        async fn fuzz(&self, _: &Build, _: &TargetSig, _: Duration) -> Result<FuzzReport> {
            Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            })
        }
    }

    #[tokio::test]
    async fn orchestrator_persists_to_sqlite() {
        let repo = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::in_memory().unwrap());
        let orch = Orchestrator::new(
            Arc::new(NoopAdapter),
            store,
            repo.path().to_path_buf(),
            Mode::Dev,
        );
        let target = TargetSig {
            language: "noop".into(),
            module: "m".into(),
            symbol: "s".into(),
            arity: None,
        };
        let art = orch.run(target, false).await.unwrap();
        assert!(art.stages_completed.contains(&LoopStage::Harvest));
        assert!(art.gate.is_some());
        // SQLite run store should exist with a completed row.
        let runs_db = repo.path().join(".ods/runs.db");
        assert!(runs_db.exists());
        let rs = RunStore::open(&runs_db).unwrap();
        let recent = rs.recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].status, RunStatus::Completed);
        // JSON mirror also written.
        assert!(repo.path().join(".ods/runs").exists());
    }
}
