//! Specialist race: run N specialists in parallel worktrees, pick the
//! winner by (passes-gate AND highest speedup lower bound).
//!
//! Budget accounting: every specialist's `LoopStats::estimated_cost_usd` is
//! threaded into the caller's running `spent_usd`. A CI-mode budget overflow
//! aborts outstanding work gracefully and the orchestrator persists a
//! partial-result artifact rather than crashing.

use crate::anthropic::{AnthropicClient, ConversationObserver, ToolUseLoop};
use crate::observe::{self, AgentEvent, EventSink};
use crate::specialist::{Specialist, SpecialistKind, SpecialistOutcome};
use crate::tools::{Sandbox, ToolHandlerMap};
use anyhow::Result;
use ods_core::{
    domain::{Hypothesis, TargetSig},
    git::Worktree,
    mode::Mode,
    LoopError, LoopStage, RunId, WorktreeHandle,
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
    /// Optional observability sink. Every specialist turn, tool call, and
    /// verdict is emitted both to tracing and (when present) this sink.
    pub sink: Option<Arc<dyn EventSink>>,
    /// Run id used for event persistence.
    pub run_id: RunId,
    /// Shared cross-specialist spend counter. When `Some`, every
    /// `ToolUseLoop` run by this race charges its per-call cost into this
    /// tracker, and bails with `LoopError::BudgetWouldExceed` before the
    /// next POST if the projected cost would push spend past the cap.
    pub budget_tracker: Option<ods_core::BudgetTracker>,
}

pub struct RaceOutput {
    pub outcomes: Vec<SpecialistOutcome>,
    pub winner: Option<WinnerRecord>,
    pub spent_usd: f64,
    pub budget_exhausted: bool,
    /// Counter-evidence gathered during the race: a retrieved recipe whose
    /// specialist abstained, had its patch rejected by the gate, or failed
    /// to produce a measurable speedup. The orchestrator persists these
    /// onto the affected recipes' `negative_history` via
    /// [`crate::harvest::record_negatives`].
    pub negative_records: Vec<(ods_recipes::RecipeId, ods_recipes::NegativeOutcome)>,
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
    let mut negative_records: Vec<(ods_recipes::RecipeId, ods_recipes::NegativeOutcome)> =
        Vec::new();
    let sink = input.sink.as_ref();
    let run_id = input.run_id;

    observe::emit(
        sink,
        &run_id,
        LoopStage::Transform,
        AgentEvent::RaceStart {
            specialists: input.plan.iter().map(|(k, _)| format!("{:?}", k)).collect(),
        },
    );

    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            tracing::warn!("ANTHROPIC_API_KEY not set; race aborted (0 specialists)");
            observe::emit(
                sink,
                &run_id,
                LoopStage::Transform,
                AgentEvent::RaceFinish {
                    winner: None,
                    total_spent_usd: 0.0,
                    budget_exhausted: false,
                },
            );
            return Ok(RaceOutput {
                outcomes,
                winner: None,
                spent_usd: 0.0,
                budget_exhausted: false,
                negative_records: vec![],
            });
        }
    };

    let client = AnthropicClient::new(api_key)?;
    std::fs::create_dir_all(&input.worktree_parent)?;

    for (specialist_idx, (kind, hyp)) in input.plan.iter().enumerate() {
        // CI-mode budget check before each specialist. Uses the shared
        // tracker when present so parallel specialists see each other's
        // spend; falls back to local `spent_usd` for Dev-mode runs.
        if let Mode::Ci(b) = &input.mode {
            let current = input
                .budget_tracker
                .as_ref()
                .map(|t| t.spent())
                .unwrap_or(spent_usd);
            // A per-specialist round on average costs ~$0.50. If there's
            // less headroom than that we short-circuit rather than burn a
            // specialist that's almost guaranteed to bail mid-conversation.
            const PER_SPECIALIST_MIN: f64 = 0.50;
            if current + PER_SPECIALIST_MIN > b.spend_cap_usd {
                budget_exhausted = true;
                break;
            }
        }

        // Include specialist_idx so multiple specialists with the same
        // (kind, category) — e.g. three FastPathSpecializer runs in one
        // race — get DISTINCT worktree directories. Without the idx
        // suffix, Worktree::create's `if target.exists() { remove_dir_all }`
        // would wipe the previous specialist's worktree before running
        // the next one. That's catastrophic when an earlier specialist
        // was the winner: the rerun-3× determinism gate later calls
        // adapter.build against `winner.worktree_path`, which by then
        // has been clobbered. Observable symptom: `determinism: None` in
        // every artifact even though the stage-21 rerun code ran.
        let tag = format!("{:?}-{}-{}", kind, hyp.category, specialist_idx);
        let wt = Worktree::create(input.repo, &tag, &input.worktree_parent)?;
        let sandbox = Sandbox::new(wt.path.clone());

        let mut loop_ = ToolUseLoop::default();
        ToolHandlerMap::register_read_only(&mut loop_, sandbox.clone());
        ToolHandlerMap::register_mutating(&mut loop_, sandbox.clone());
        if let Some(t) = input.budget_tracker.as_ref() {
            loop_ = loop_.with_budget_tracker(t.clone());
        }

        let spec = Specialist::new(*kind);
        let initial = compose_user_prompt(kind, hyp, input.target, &input.recipe_snippets);

        observe::emit(
            sink,
            &run_id,
            LoopStage::Transform,
            AgentEvent::SpecialistStart {
                kind: kind_name(*kind),
                target: input.target.to_string(),
                hypothesis: hyp.rationale.clone(),
                seed_recipe_id: hyp.seed_recipe_id.clone(),
            },
        );

        let spec_name = kind_name(*kind);
        let observer = build_observer(sink.cloned(), run_id, &spec_name);
        let (stats, final_text, _convo) = match loop_
            .run_observed(&client, spec.system_prompt(), &initial, Some(&observer))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // Detect the hard per-call budget gate so we stop racing
                // new specialists instead of silently marking each one as
                // "failed conversation" and burning a worktree per error.
                let hit_budget = e
                    .downcast_ref::<LoopError>()
                    .map(|le| matches!(le, LoopError::BudgetWouldExceed { .. }))
                    .unwrap_or(false);
                tracing::warn!(
                    kind = %kind_name(*kind),
                    err = %e,
                    err_chain = %format!("{e:#}"),
                    hit_budget,
                    "specialist conversation failed"
                );
                observe::emit(
                    sink,
                    &run_id,
                    LoopStage::Transform,
                    AgentEvent::SpecialistFinish {
                        kind: kind_name(*kind),
                        patch_attempted: false,
                        accepted: false,
                        spent_usd: 0.0,
                        tokens_in: 0,
                        tokens_out: 0,
                    },
                );
                if hit_budget {
                    budget_exhausted = true;
                    drop(wt);
                    break;
                }
                continue;
            }
        };
        let cost = stats.estimated_cost_usd();
        spent_usd += cost;

        // Patch capture: ask git what changed on disk in the
        // specialist's worktree. The agent only has edit_file /
        // write_file as mutation tools, so any change is on disk and
        // git-visible by construction. The diff is guaranteed
        // well-formed because git produced it from the actual
        // filesystem state.
        let outcome = SpecialistOutcome {
            kind: *kind,
            patch_diff: capture_worktree_diff(&wt.path),
            rationale: final_text.clone(),
            tokens_in: stats.input_tokens,
            tokens_out: stats.output_tokens,
            estimated_cost_usd: cost,
        };
        outcomes.push(outcome.clone());

        let Some(diff) = outcome.patch_diff.clone() else {
            // Specialist principled-abstained. If the hypothesis was seeded
            // by a specific recipe, record that recipe didn't fit here.
            if let Some(id) = &hyp.seed_recipe_id {
                negative_records.push((
                    ods_recipes::RecipeId(id.clone()),
                    ods_recipes::NegativeOutcome::Abstained,
                ));
            }
            observe::emit(
                sink,
                &run_id,
                LoopStage::Transform,
                AgentEvent::SpecialistFinish {
                    kind: kind_name(*kind),
                    patch_attempted: false,
                    accepted: false,
                    spent_usd: cost,
                    tokens_in: stats.input_tokens,
                    tokens_out: stats.output_tokens,
                },
            );
            drop(wt);
            continue;
        };
        observe::emit(
            sink,
            &run_id,
            LoopStage::Transform,
            AgentEvent::PatchProposed {
                specialist: kind_name(*kind),
                diff_bytes: diff.len(),
            },
        );
        // The agent's edit_file/write_file calls have already mutated
        // the worktree; `diff` is the git-captured copy we keep for the
        // artifact. Verify + bench what's on disk now.
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
        // Only feed the fuzz report to the gate when fuzzing actually ran
        // (minutes > 0). A zero-minute report means the adapter silently
        // skipped (e.g. `cargo-fuzz` not installed) and should be treated as
        // "no fuzz info" rather than "fuzzed for 0 minutes".
        let fuzz = input
            .adapter
            .fuzz(&build, input.target, input.fuzz_budget)
            .await
            .ok()
            .filter(|r| r.minutes > 0);
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
            if let Some(id) = &hyp.seed_recipe_id {
                negative_records.push((
                    ods_recipes::RecipeId(id.clone()),
                    ods_recipes::NegativeOutcome::RejectedByGate,
                ));
            }
            observe::emit(
                sink,
                &run_id,
                LoopStage::Transform,
                AgentEvent::PatchRejected {
                    specialist: kind_name(*kind),
                    reasons: gate.reasons.clone(),
                },
            );
            observe::emit(
                sink,
                &run_id,
                LoopStage::Transform,
                AgentEvent::SpecialistFinish {
                    kind: kind_name(*kind),
                    patch_attempted: true,
                    accepted: false,
                    spent_usd: cost,
                    tokens_in: stats.input_tokens,
                    tokens_out: stats.output_tokens,
                },
            );
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
            if let Some(id) = &hyp.seed_recipe_id {
                negative_records.push((
                    ods_recipes::RecipeId(id.clone()),
                    ods_recipes::NegativeOutcome::NoMeasuredSpeedup,
                ));
            }
            observe::emit(
                sink,
                &run_id,
                LoopStage::Transform,
                AgentEvent::SpecialistFinish {
                    kind: kind_name(*kind),
                    patch_attempted: true,
                    accepted: false,
                    spent_usd: cost,
                    tokens_in: stats.input_tokens,
                    tokens_out: stats.output_tokens,
                },
            );
            drop(wt);
            continue;
        }

        observe::emit(
            sink,
            &run_id,
            LoopStage::Transform,
            AgentEvent::SpecialistFinish {
                kind: kind_name(*kind),
                patch_attempted: true,
                accepted: true,
                spent_usd: cost,
                tokens_in: stats.input_tokens,
                tokens_out: stats.output_tokens,
            },
        );

        // Categories that change runtime behaviour (GC tuning, allocator
        // choice, pre-fork hooks) can't be validated by a single-process
        // bench — the signal is fleet-level. Until a canary gate lands,
        // these surface as suggestions via the outcome list but never
        // compete for the "winner" slot and so never drive an auto-apply
        // PR. See `OptimizationCategory::requires_canary`.
        if hyp.category.requires_canary() {
            tracing::info!(
                kind = %kind_name(*kind),
                category = %hyp.category,
                "runtime-config patch produced but withheld from winner race \
                 (requires canary gate, not wall-clock bench)"
            );
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

    observe::emit(
        sink,
        &run_id,
        LoopStage::Transform,
        AgentEvent::RaceFinish {
            winner: winner.as_ref().map(|w| format!("{:?}", w.outcome.kind)),
            total_spent_usd: spent_usd,
            budget_exhausted,
        },
    );

    Ok(RaceOutput {
        outcomes,
        winner,
        spent_usd,
        budget_exhausted,
        negative_records,
    })
}

fn build_observer(
    sink: Option<Arc<dyn EventSink>>,
    run_id: RunId,
    specialist: &str,
) -> ConversationObserver<'static> {
    let spec = specialist.to_string();
    let sink_turn = sink.clone();
    let sink_reason = sink.clone();
    let sink_call = sink.clone();
    let sink_result = sink.clone();
    let spec_turn = spec.clone();
    let spec_reason = spec.clone();
    let spec_call = spec.clone();
    let spec_result = spec.clone();
    ConversationObserver {
        on_turn: Box::new(move |iter, stop, tin, tout, cr, cc| {
            observe::emit(
                sink_turn.as_ref(),
                &run_id,
                LoopStage::Transform,
                AgentEvent::Turn {
                    specialist: spec_turn.clone(),
                    iteration: iter,
                    stop_reason: stop,
                    input_tokens: tin,
                    output_tokens: tout,
                    cache_read_tokens: cr,
                    cache_creation_tokens: cc,
                },
            );
        }),
        on_reasoning: Box::new(move |iter, text| {
            if text.trim().is_empty() {
                return;
            }
            observe::emit(
                sink_reason.as_ref(),
                &run_id,
                LoopStage::Transform,
                AgentEvent::Reasoning {
                    specialist: spec_reason.clone(),
                    iteration: iter,
                    text_preview: observe::preview(text, 400),
                },
            );
        }),
        on_tool_call: Box::new(move |iter, tool, input| {
            observe::emit(
                sink_call.as_ref(),
                &run_id,
                LoopStage::Transform,
                AgentEvent::ToolCall {
                    specialist: spec_call.clone(),
                    iteration: iter,
                    tool: tool.to_string(),
                    input_preview: observe::preview(&input.to_string(), 240),
                },
            );
        }),
        on_tool_result: Box::new(move |iter, tool, ok, result| {
            observe::emit(
                sink_result.as_ref(),
                &run_id,
                LoopStage::Transform,
                AgentEvent::ToolResult {
                    specialist: spec_result.clone(),
                    iteration: iter,
                    tool: tool.to_string(),
                    ok,
                    result_preview: observe::preview(result, 320),
                },
            );
        }),
    }
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
         2. If the project has an existing bench that exercises the target, \
         use it via run_bench. If `benches/ods_auto_*.rs` exists and contains \
         a `black_box(())` no-op placeholder, you MUST rewrite its `b.iter(...)` \
         block via edit_file to actually invoke the target function with \
         realistic inputs — otherwise the pre/post comparison is pure noise \
         and the race will reject your patch regardless of correctness.\n\
         3. Use edit_file (surgical string replace) and write_file \
         (full overwrite) to mutate the worktree. The race captures the \
         canonical diff via `git diff` after your conversation, so you \
         never need to hand-format a unified diff.\n\
         4. After every edit, call run_tests to verify semantics are \
         preserved.\n\
         5. Call run_bench to confirm a measurable improvement before \
         finishing the turn.\n\
         6. If you conclude the hypothesis does not apply to this target, \
         finish with NO edits — the race treats a clean worktree as a \
         principled abstain rather than a forced bad patch.\n",
    );
    s
}

/// After the specialist conversation ends, the worktree filesystem
/// reflects every edit_file / write_file call the agent made. We ask
/// git for the canonical unified diff against the worktree's HEAD —
/// guaranteed well-formed because git produced it. Returns `None` when
/// the worktree is clean (specialist abstained or made only no-op edits).
fn capture_worktree_diff(worktree: &Path) -> Option<String> {
    use std::process::Command;
    let out = Command::new("git")
        .args([
            "diff",
            "--no-color",
            "--no-ext-diff",
            // Include untracked files so newly-created sources land
            // in the diff too. `-N` (intent-to-add) is the standard
            // trick: it makes `git diff` treat untracked files as
            // empty additions.
            "HEAD",
        ])
        .current_dir(worktree)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut diff = String::from_utf8(out.stdout).ok()?;
    // Catch newly-created files that `git diff HEAD` skips.
    let _ = Command::new("git")
        .args(["add", "-N", "."])
        .current_dir(worktree)
        .output();
    let untracked = Command::new("git")
        .args(["diff", "--no-color", "--no-ext-diff"])
        .current_dir(worktree)
        .output()
        .ok()?;
    if untracked.status.success() {
        let extra = String::from_utf8_lossy(&untracked.stdout);
        if !extra.trim().is_empty() && !diff.contains(extra.trim()) {
            if !diff.is_empty() && !diff.ends_with('\n') {
                diff.push('\n');
            }
            diff.push_str(&extra);
        }
    }
    if diff.trim().is_empty() {
        None
    } else {
        Some(diff)
    }
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
    fn capture_worktree_diff_returns_none_for_clean_worktree() {
        let dir = tempfile::tempdir().unwrap();
        let _ = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status();
        // Allow git operations on a fresh repo with no commits — we just
        // assert the function doesn't panic and returns None.
        let captured = capture_worktree_diff(dir.path());
        assert!(captured.is_none() || captured.unwrap().is_empty());
    }

    #[test]
    fn capture_worktree_diff_picks_up_edits_and_new_files() {
        let dir = tempfile::tempdir().unwrap();
        // Test fixture: disable gpg signing for commits we make purely
        // to seed the test repo. Local-config-only; doesn't affect the
        // user's git config.
        for cmd in [
            vec!["init", "-q"],
            vec!["config", "user.email", "ods@test"],
            vec!["config", "user.name", "ods"],
            vec!["config", "commit.gpgsign", "false"],
        ] {
            std::process::Command::new("git")
                .args(&cmd)
                .current_dir(dir.path())
                .status()
                .unwrap();
        }
        std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "a.txt"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        let commit_status = std::process::Command::new("git")
            .args(["commit", "-q", "-m", "init"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        if !commit_status.success() {
            // Some sandboxed CI environments still refuse commits even
            // with signing disabled. Skip rather than false-fail.
            eprintln!("skipping: git commit refused in this env");
            return;
        }
        std::fs::write(dir.path().join("a.txt"), "HELLO\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "new file\n").unwrap();
        let diff = capture_worktree_diff(dir.path()).expect("non-empty diff");
        assert!(diff.contains("HELLO"));
        assert!(diff.contains("new file"));
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
