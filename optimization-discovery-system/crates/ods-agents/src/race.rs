//! Specialist race: run N specialists in parallel worktrees, pick the
//! winner by (passes-gate AND highest speedup lower bound).
//!
//! Budget accounting: every specialist's `LoopStats::estimated_cost_usd` is
//! threaded into the caller's running `spent_usd`. A CI-mode budget overflow
//! aborts outstanding work gracefully and the orchestrator persists a
//! partial-result artifact rather than crashing.

use crate::anthropic::{AnthropicClient, ToolUseLoop};
use crate::specialist::{Specialist, SpecialistKind, SpecialistOutcome};
use crate::tools::{Sandbox, ToolHandlerMap};
use anyhow::Result;
use ods_core::{
    domain::{Hypothesis, TargetSig},
    git::Worktree,
    mode::Mode,
    LoopError, WorktreeHandle,
};
use ods_lang::{BenchReport, LanguageAdapter, Patch, TestScope};
use ods_measure::{compare, Sample, SpeedupVerdict};
use ods_verify::{GateDecision, GateInput, ZeroDiffGate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub struct RaceInput<'a> {
    pub repo: &'a Path,
    pub target: &'a TargetSig,
    pub adapter: Arc<dyn LanguageAdapter>,
    pub plan: Vec<(SpecialistKind, Hypothesis)>,
    pub mode: Mode,
    pub pre_bench: Option<BenchReport>,
    pub recipe_snippets: Vec<String>,
    pub worktree_parent: PathBuf,
    pub fuzz_budget: Duration,
}

pub struct RaceOutput {
    pub outcomes: Vec<SpecialistOutcome>,
    pub winner: Option<WinnerRecord>,
    pub spent_usd: f64,
    pub budget_exhausted: bool,
}

pub struct WinnerRecord {
    pub outcome: SpecialistOutcome,
    pub patch: Patch,
    pub post_bench: BenchReport,
    pub verdict: SpeedupVerdict,
    pub worktree_path: PathBuf,
    /// Kept alive for the duration the caller wants the worktree; drop
    /// cleans up.
    pub _handle: WorktreeHandle,
}

/// Run each `(kind, hypothesis)` in a separate worktree. The
/// `AnthropicClient` must be provided by the caller (read from
/// `ANTHROPIC_API_KEY` env so the key never enters argv).
pub async fn run_specialists(input: RaceInput<'_>) -> Result<RaceOutput> {
    let mut outcomes = Vec::new();
    let mut spent_usd = 0.0;
    let mut winners: Vec<WinnerRecord> = Vec::new();
    let mut budget_exhausted = false;

    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            tracing::warn!("ANTHROPIC_API_KEY not set; race aborted (0 specialists)");
            return Ok(RaceOutput {
                outcomes,
                winner: None,
                spent_usd: 0.0,
                budget_exhausted: false,
            });
        }
    };

    let client = AnthropicClient::new(api_key)?;
    std::fs::create_dir_all(&input.worktree_parent)?;

    for (kind, hyp) in &input.plan {
        // CI-mode budget check before each specialist.
        if let Mode::Ci(b) = &input.mode {
            if spent_usd >= b.spend_cap_usd {
                budget_exhausted = true;
                break;
            }
        }

        let tag = format!("{:?}-{}", kind, hyp.category);
        let wt = Worktree::create(input.repo, &tag, &input.worktree_parent)?;
        let sandbox = Sandbox::new(wt.path.clone());

        let mut loop_ = ToolUseLoop::default();
        ToolHandlerMap::register_read_only(&mut loop_, sandbox.clone());
        ToolHandlerMap::register_mutating(&mut loop_, sandbox.clone());

        let spec = Specialist::new(*kind);
        let initial = compose_user_prompt(kind, hyp, input.target, &input.recipe_snippets);

        let (stats, final_text, _convo) = match loop_
            .run(&client, spec.system_prompt(), &initial)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(kind = %kind_name(*kind), err = %e, "specialist conversation failed");
                continue;
            }
        };
        let cost = stats.estimated_cost_usd();
        spent_usd += cost;

        let outcome = SpecialistOutcome {
            kind: *kind,
            patch_diff: extract_last_diff(&final_text),
            rationale: final_text.clone(),
            tokens_in: stats.input_tokens,
            tokens_out: stats.output_tokens,
            estimated_cost_usd: cost,
        };
        outcomes.push(outcome.clone());

        let Some(diff) = outcome.patch_diff.clone() else {
            drop(wt);
            continue;
        };
        // The apply_patch tool has already mutated the worktree during the
        // conversation; `diff` is a copy we keep for the artifact. Verify +
        // bench what's on disk now.
        let patch = Patch {
            unified_diff: diff,
            edits: vec![],
        };
        let build = match input.adapter.build(&wt.path, Some(&patch)).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(err = %e, "build after patch failed; skipping winner candidacy");
                drop(wt);
                continue;
            }
        };
        let tests = input
            .adapter
            .run_tests(&build, TestScope::Full)
            .await
            .unwrap_or(ods_lang::TestReport {
                passed: 0,
                failed: 1,
                skipped: 0,
                log_path: None,
            });
        let fuzz = input
            .adapter
            .fuzz(&build, input.target, input.fuzz_budget)
            .await
            .ok();
        let gate_input = GateInput {
            tests,
            property_tests: None,
            fuzz,
            semver: None,
            downstream_tests: vec![],
            touches_public_api: false,
            is_dep_bump: matches!(*kind, SpecialistKind::DependencyOptimizer),
        };
        let gate = ZeroDiffGate::default()
            .evaluate(&gate_input)
            .unwrap_or_else(|_| ods_verify::GateReport {
                decision: GateDecision::Fail,
                reasons: vec!["gate evaluation failed".into()],
            });
        if !matches!(gate.decision, GateDecision::Pass) {
            tracing::info!(reasons = ?gate.reasons, "specialist patch rejected by gate");
            drop(wt);
            continue;
        }
        let post_bench = match input.adapter.run_bench(&build, input.target).await {
            Ok(b) => b,
            Err(_) => {
                drop(wt);
                continue;
            }
        };
        let verdict = match (
            input.pre_bench.as_ref().and_then(|b| b.samples.first()),
            post_bench.samples.first(),
        ) {
            (Some(pre), Some(post)) => {
                let pre_s = Sample {
                    name: "pre".into(),
                    values_ns: vec![pre.ns_per_iter; 30],
                };
                let post_s = Sample {
                    name: "post".into(),
                    values_ns: vec![post.ns_per_iter; 30],
                };
                compare(&pre_s, &post_s)
            }
            _ => {
                drop(wt);
                continue;
            }
        };
        if !verdict.accepted {
            drop(wt);
            continue;
        }

        winners.push(WinnerRecord {
            outcome,
            patch,
            post_bench,
            verdict,
            worktree_path: wt.path.clone(),
            _handle: wt,
        });
    }

    // Pick winner by largest speedup lower-bound.
    winners.sort_by(|a, b| {
        b.verdict
            .speedup_lower
            .partial_cmp(&a.verdict.speedup_lower)
            .unwrap()
    });
    let winner = winners.into_iter().next();

    Ok(RaceOutput {
        outcomes,
        winner,
        spent_usd,
        budget_exhausted,
    })
}

fn kind_name(k: SpecialistKind) -> String {
    format!("{:?}", k)
}

fn compose_user_prompt(
    kind: &SpecialistKind,
    hyp: &Hypothesis,
    target: &TargetSig,
    recipe_snippets: &[String],
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "You are the {:?} specialist. Target: `{}`.\n",
        kind, target
    ));
    s.push_str(&format!("Hypothesis: {}\n", hyp.rationale));
    if let Some(id) = &hyp.seed_recipe_id {
        s.push_str(&format!("Suggested recipe: {}\n", id));
    }
    if !recipe_snippets.is_empty() {
        s.push_str("\nRelevant recipe snippets:\n");
        for snip in recipe_snippets {
            s.push_str(&format!("- {}\n", snip));
        }
    }
    s.push_str(
        "\nGuidelines:\n\
         1. Use read_file/list_dir/ast_query to explore the target.\n\
         2. Produce a minimal unified-diff patch.\n\
         3. Call apply_patch with your diff, then run_tests to verify.\n\
         4. Finish with a short rationale and include the final unified diff \
         verbatim in a ```diff code block so the race can extract it.\n",
    );
    s
}

/// Extract the last fenced ```diff``` block from the final assistant text.
fn extract_last_diff(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?s)```diff\n(.*?)```").ok()?;
    re.captures_iter(text)
        .last()
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

pub fn budget_exceeded(mode: &Mode, spent: f64) -> Option<LoopError> {
    if let Mode::Ci(b) = mode {
        if spent > b.spend_cap_usd {
            return Some(LoopError::BudgetExhausted {
                stage: ods_core::LoopStage::Transform,
                elapsed_secs: 0,
                spent_usd: spent,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_last_diff_block() {
        let text = "prelude\n```diff\n--- a/x\n+++ b/x\n@@\n-a\n+b\n```\nokay";
        let d = extract_last_diff(text).unwrap();
        assert!(d.contains("@@"));
        assert!(d.contains("+b"));
    }

    #[test]
    fn prompt_mentions_target_and_kind() {
        let hyp = Hypothesis {
            category: ods_core::OptimizationCategory::SyscallElimination,
            target: TargetSig {
                language: "rust".into(),
                module: "m".into(),
                symbol: "s".into(),
                arity: None,
            },
            rationale: "why".into(),
            seed_recipe_id: Some("r1".into()),
        };
        let p = compose_user_prompt(&SpecialistKind::SyscallEliminator, &hyp, &hyp.target, &[]);
        assert!(p.contains("SyscallEliminator"));
        assert!(p.contains("rust::m::s"));
        assert!(p.contains("r1"));
    }
}
