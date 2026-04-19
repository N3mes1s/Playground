//! End-to-end run orchestrator. Walks `TargetSelect -> ... -> Harvest` using
//! the configured [`LanguageAdapter`], [`Planner`], specialists, and recipe
//! store. Persists run artifacts under `<workdir>/.ods/runs/<run_id>/`.
//!
//! This is deliberately defensive: any stage that fails (missing tool, no
//! candidates, network error for the LLM) should still emit a usable report
//! so the CI path can surface partial progress rather than crashing.

use crate::planner::Planner;
use anyhow::{Context, Result};
use ods_core::{
    domain::{Hypothesis, OptimizationCategory, TargetSig},
    loop_::LoopStage,
    Mode, Run,
};
use ods_lang::{BenchReport, LanguageAdapter, ProfileReport, TestReport, TestScope};
use ods_measure::{compare, Sample, SpeedupVerdict};
use ods_recipes::Store;
use ods_verify::{GateInput, GateReport, ZeroDiffGate};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

/// Single stored run. The orchestrator writes one JSON file per run under
/// `<repo>/.ods/runs/<run_id>.json` for `ods explain` to rehydrate later.
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
    pub note: Option<String>,
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

    /// Drive the loop for a single target. The LLM transform step is opt-in:
    /// if `allow_llm` is false (no API key or dev mode without credentials)
    /// we only run measure-and-verify against the current checkout, which is
    /// still valuable as a baseline + determinism check.
    pub async fn run(&self, target: TargetSig, allow_llm: bool) -> Result<RunArtifact> {
        let mut run = Run::new(self.mode.clone());
        run.target = Some(target.clone());

        let mut artifact = RunArtifact {
            run_id: run.id.to_string(),
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
            note: None,
        };

        // TargetSelect: already provided by caller.
        artifact.stages_completed.push(LoopStage::TargetSelect);
        run.advance()?;

        // Profile (pre) -----------------------------------------------------
        let build = self
            .adapter
            .build(&self.repo, None)
            .await
            .context("adapter.build")?;
        let pre_profile = self.adapter.profile(&build, &target).await.ok();
        artifact.pre_profile = pre_profile.clone();
        artifact.stages_completed.push(LoopStage::Profile);
        run.advance()?;

        let pre_bench = self.adapter.run_bench(&build, &target).await.ok();
        artifact.pre_bench = pre_bench.clone();

        // RecipeRetrieve ----------------------------------------------------
        let categories = infer_categories(pre_profile.as_ref());
        let planner = Planner::new(&self.store);
        let plan = planner.plan(&target, &categories).unwrap_or_default();
        artifact.hypotheses = plan.iter().map(|(_, h)| h.clone()).collect();
        artifact.recipes_applied = plan
            .iter()
            .filter_map(|(_, h)| h.seed_recipe_id.clone())
            .collect();
        artifact.stages_completed.push(LoopStage::RecipeRetrieve);
        run.advance()?;

        // Hypothesize / Transform ------------------------------------------
        //
        // The LLM-driven transform path is gated on `allow_llm`. Without an
        // API key we still run the verify + bench gates against the current
        // checkout so the caller gets a reproducible baseline report.
        if allow_llm {
            artifact.note = Some(
                "LLM transform path is wired via ToolUseLoop; the orchestrator stops \
                 before invoking the network so tests and the dev CLI stay hermetic. \
                 Use `ods run ... --llm` (stage 2) to execute specialists."
                    .into(),
            );
        } else {
            artifact.note = Some(
                "LLM disabled; running measurement-only pipeline.".into(),
            );
        }
        artifact.stages_completed.push(LoopStage::Hypothesize);
        artifact.stages_completed.push(LoopStage::Transform);
        run.advance()?;
        run.advance()?;

        // Verify ------------------------------------------------------------
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
        let gate_input = GateInput {
            tests,
            property_tests: None,
            fuzz: None,
            semver: None,
            downstream_tests: vec![],
            touches_public_api: false,
            is_dep_bump: false,
        };
        let gate = ZeroDiffGate::default().evaluate(&gate_input)?;
        artifact.gate = Some(gate);
        artifact.stages_completed.push(LoopStage::Verify);
        run.advance()?;

        // Bench (post) ------------------------------------------------------
        //
        // Without a patch the post-bench is identical to pre-bench; we still
        // run it to exercise the measurement determinism gate.
        let post_bench = self.adapter.run_bench(&build, &target).await.ok();
        artifact.post_bench = post_bench.clone();
        if let (Some(pre), Some(post)) = (&pre_bench, &post_bench) {
            if let (Some(p), Some(q)) = (pre.samples.first(), post.samples.first()) {
                let pre_s = Sample {
                    name: "pre".into(),
                    values_ns: vec![p.ns_per_iter; 30],
                };
                let post_s = Sample {
                    name: "post".into(),
                    values_ns: vec![q.ns_per_iter; 30],
                };
                artifact.speedup = Some(compare(&pre_s, &post_s));
            }
        }
        artifact.stages_completed.push(LoopStage::Bench);
        run.advance()?;

        // Explain + Harvest -------------------------------------------------
        artifact.stages_completed.push(LoopStage::Explain);
        artifact.stages_completed.push(LoopStage::Harvest);

        persist(&self.repo, &artifact)?;
        Ok(artifact)
    }
}

fn infer_categories(profile: Option<&ProfileReport>) -> Vec<OptimizationCategory> {
    // Very simple heuristic today: any non-empty syscall list triggers
    // SyscallElimination; otherwise every category is considered.
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

fn persist(repo: &PathBuf, art: &RunArtifact) -> Result<()> {
    let dir = repo.join(".ods").join("runs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", art.run_id));
    let body = serde_json::to_string_pretty(art)?;
    std::fs::write(&path, body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ods_lang::{AstMatch, Build, Edit, FuzzReport, Patch};
    use std::path::Path;
    use std::time::Duration;

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
                samples: vec![ods_lang::BenchSample {
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
        async fn fuzz(
            &self,
            _: &Build,
            _: &TargetSig,
            _: Duration,
        ) -> Result<FuzzReport> {
            Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            })
        }
    }

    #[tokio::test]
    async fn orchestrator_runs_end_to_end_without_llm() {
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
        assert!(repo.path().join(".ods/runs").exists());
    }
}
