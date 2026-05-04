# Architecture

End-to-end map of the playground. Use this as the entry point if you
land here cold.

## What this is

A research playground exploring **multi-stakeholder rollout planning
for managed coding agents**: the human approves a plan, the agent
executes the diffs. Six experiments + a unified evaluation /
continuous-improvement loop sit on a shared substrate (`mirofish_lab/`)
of CAMEL-AI-style agents, structured-constraint debate, formal
verification, chaos analysis, and a 20k-element evaluation dataset.

## Pipeline at a glance

```
┌─────────────────────────────────────────────────────────────────┐
│ INTENT                                                          │
│   markdown describing a proposed change (issue/PR/migration)    │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ STAKEHOLDER CONSTRAINTS  (mirofish_lab.rollout)                 │
│   6 personas (BackendOwner, DataPlatform, SRE, Security,        │
│   ProductPM, ConsumerSubsystem) emit STRUCTURED constraints     │
│   in parallel. Each constraint has axis + summary + scope +     │
│   gate + rollback + blocking.                                   │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ CODEBASE GROUNDING (optional)  (mirofish_lab.grounding)         │
│   Repo path → LLM-generated search patterns → AST + regex       │
│   scan → matches by file:line. Findings appended to the         │
│   intent so personas + sequencer reference real code.           │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ PARETO SEQUENCERS  (mirofish_lab.pareto / pareto_frontier)      │
│   N (default 4-6) Sequencer agents with different optimisation  │
│   axes (speed-leaning, safety-leaning, cost-leaning, balanced,  │
│   plus mixed weights). Each produces a partial-order plan as    │
│   JSON: steps + dependencies + gates + rollbacks +              │
│   observability.                                                │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ VERIFICATION  (mirofish_lab.verify + verify_smt)                │
│   Structural: Tarjan SCC for cycles, reachability,              │
│     blocking-constraint coverage by token overlap.              │
│   Z3 SMT: integer-position ordering with named tracked          │
│     assertions; on UNSAT, extract minimal unsat core            │
│     translated to natural-language explanations.                │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ CHAOS ANALYSIS  (mirofish_lab.chaos / chaos_static / search /   │
│                  montecarlo)                                    │
│   - LLM-based per-step probe: "if step S fails, what cascades?" │
│   - Static graph: exact cascade by transitive closure           │
│   - Adversarial search: ChaosAttacker LLM proposes worst-K      │
│     failure combos, scored by static cascade                    │
│   - Monte Carlo: per-gate failure priors, N-sample simulation   │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ NSGA-II PARETO PICK  (mirofish_lab.pareto_frontier)             │
│   Non-dominated sort across (fragility, severity,               │
│   rollback_failure_rate, steps, neg_coverage). Crowding         │
│   distance for spread. User-supplied utility weights project    │
│   to a single recommendation; per-plan rationale always shown.  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ HARDENER (closed loop, optional)  (mirofish_lab.chaos_hardener) │
│   Reads chaos findings + SMT unsat core; LLM-generated revised  │
│   plan; re-verify; loop until threshold or no improvement.      │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ AGENT BACKLOG (cli_grounded only)                               │
│   Each step gets `file_paths` + `agent_instructions` matched    │
│   by token overlap against the grounding findings; an executor  │
│   coding-agent can dispatch step-by-step.                       │
└─────────────────────────────────────────────────────────────────┘
```

## Five user-facing CLIs (verified-rollout/)

Pick the one that matches your goal:

| CLI | When to use it |
|---|---|
| `cli_pro.py <intent.md>` | Full Pareto + verify + chaos + recommendation. The default if you just want a plan. |
| `cli_grounded.py <intent.md> --repo PATH` | Same pipeline + repo scan; plan steps reference real files / lines / symbols and include `agent_instructions` for an executor agent. |
| `cli_chaos.py <intent.md>` | Deep chaos analysis: LLM probe + static cascade + adversarial search + Monte Carlo + cross-validation. Use after `cli_pro` to dig into a fragile plan. |
| `cli_harden.py <intent.md> --threshold 0.3` | Closed-loop hardener: chaos → harden → re-verify until threshold met or no improvement. |
| `cli_chaos.py` (single plan) | Same as above but on one plan rather than the Pareto frontier. |

## Subdirectories

| Path | Purpose |
|---|---|
| `mirofish_lab/` | Shared substrate. Personas, agents, simulation primitives, verification, chaos, grounding, NSGA-II Pareto. |
| `verified-rollout/` | The five CLIs above + their generated reports under `reports/`. |
| `pr-review-rehearsal/` | Multi-reviewer-persona PR critique. |
| `pre-flight-rehearsal/` | Multi-style implementer plans (Minimalist / Defensive / TestFirst / RefactorHappy) ranked by judge. |
| `adversarial-security-sim/` | Triage existing audit reports via Attacker / Defender debate. |
| `blast-radius-prediction/` | Subsystem agents react to a diff; per-subsystem risk roll-up. |
| `rollout-rehearsal/` | The 6-stakeholder structured-constraint planner. |
| `recursive-lm-security-audit/` | DSPy-based security scanner. Pre-existing, used as a downstream consumer. |
| `vulnllm-analyzer/` | Modal-GPU-served VulnLLM-R-7B analyzer. Pre-existing. |
| `dataset/` | The 20,479-element evaluation corpus + bench tooling. |
| `validation/` | Continuous-improvement loop: warnings, A/B harness, auto-calibrator, GEPA optimizer, drift check, run log, feedback recorder. |
| `fixtures/` | Pre-fetched intent / PR / diff fixtures used by experiments without network. |

## The bench (dataset/)

The 20,479-element evaluation corpus drives every quantitative claim
in the project.

| Source | Count | Origin |
|---|---|---|
| `swebench_verified` | 500 | HF `princeton-nlp/SWE-bench_Verified` |
| `swebench_pro` | 731 | HF `ScaleAI/SWE-bench_Pro` |
| `swebench_original` | 8,800 | HF `princeton-nlp/SWE-bench` (test+dev+train, capped) |
| `multi_swebench` | 257 | HF `ByteDance-Seed/Multi-SWE-bench` (streaming) |
| `danluu_postmortems` | 191 | git clone `danluu/post-mortems`, parse README |
| `synthetic` | 10,000 | 5-axis template generator (20 stacks × 10 changes × 5 contexts × 5 scales) |

`dataset/bench/bench_runner.py --judge` runs the pipeline on a
stratified sample, applies the LLM-judge scorer
(`dataset/bench/llm_judge.py`), and produces caught/partial/missed +
SMT-feasibility + winner-family metrics per source.

`dataset/bench/bench_ab.py` runs two configs on the SAME pinned
sample and emits a verdict.

## The continuous-improvement loop (validation/)

Five tools, layered:

```
RUNS                    RUN_LOG                AUTO_CALIBRATE
(bench, cli_*, ...)  →  (warning detection) →  (fix proposal)
                                                      │
                                                      ▼
                                              BENCH_AB --judge
                                              (statistical A/B
                                               on stratified
                                               20k corpus)
                                                      │
                                                      ▼
                                              GEPA_OPTIMIZER
                                              (self-evolving prompts:
                                               trace collection →
                                               reflector → bench-eval
                                               → held-out validation)
                                                      │
                                                      ▼
                                              CALIBRATIONS.JSONL
                                              (audit log)
                                                      │
                                                      ▼
                                              git commit (--apply --commit)
```

| Tool | Function |
|---|---|
| `validation/run_log.py` | Walks every committed `*.json` sidecar; emits `RUN_LOG.md` with winner-family bias / SMT-feasibility / avg-fragility warnings. |
| `validation/feedback.py` | CLI to record actual production outcomes for a run (which gates fired, which constraints were wrong) into `feedback.jsonl`. |
| `validation/ab_harness.py` | Legacy 2-intent internal-metric A/B. |
| `validation/dead_pattern_detector.py` | Walks SearchPlanner outputs across runs; flags patterns that produced 0 matches in ≥2 runs. |
| `validation/auto_calibrate.py` | Reads warnings (or `--auto`); proposes fixes from a registry; A/B tests; optionally `--apply --commit`s the winner. |
| `validation/gepa_optimizer.py` | GEPA-style autonomous prompt optimisation: failure-trace collection → LLM reflector → candidate `patch_block`s → bench evaluation → held-out validation. |
| `validation/drift_check.py` | Re-runs a fixed reference suite under the current model and compares to a committed baseline; red/yellow/green lights. |

## Substrate (mirofish_lab/)

| Module | What it provides |
|---|---|
| `agent.py` | `Agent` wrapper: CAMEL-AI `ChatAgent` with OpenAI-direct fallback, persona-bound, `LocalMemory`. |
| `personas.py` | Reusable personas (reviewer archetypes, implementer styles, attacker/defender, judge). |
| `rollout.py` | `STAKEHOLDER_PERSONAS` (6) + `Sequencer` + `Constraint` / `PlanStep` dataclasses + JSON extractor. |
| `pareto.py` | `PARETO_SEQUENCERS` (aggressive / balanced / conservative) with shared `BASE_TAIL`. |
| `pareto_frontier.py` | NSGA-II non-dominated sort, crowding distance, `UtilityWeights` presets, ASCII chart. |
| `verify.py` | Structural verification (Tarjan SCC, reachability, gate validity, coverage). |
| `verify_smt.py` | Z3-backed SMT verification with minimal unsat-core extraction. |
| `chaos.py` | LLM-based chaos probe (per-step + multi-failure pairs + recovery taxonomy). |
| `chaos_static.py` | Pure graph-based exact cascade computation. |
| `chaos_search.py` | Adversarial chaos search (LLM-proposed candidates + static scoring). |
| `chaos_montecarlo.py` | Per-gate failure-rate priors + N-sample simulation. |
| `chaos_hardener.py` | Closed-loop plan hardener. |
| `simulation.py` | `parallel_run`, `debate`, `round_table` primitives. |
| `grounding.py` | Generic codebase grounding: LLM SearchPlanner + AST/regex scanner + findings summary. |
| `repo.py` | AST symbol extraction + grep-based caller detection + subsystem clustering. |
| `github.py` | Public-API helpers for PR + issue fetch. |
| `report.py` | Tiny markdown report builder. |
| `memory.py` | `LocalMemory` (JSONL-backed agent log). |
| `config.py` | Env loading + `models.list()` runtime check. |

## How to navigate by goal

- **"I just want a rollout plan"** → `verified-rollout/cli_pro.py <intent.md>`
- **"I have a real repo and want concrete file references"** → `verified-rollout/cli_grounded.py <intent.md> --repo PATH`
- **"My plan looks fragile, why?"** → `verified-rollout/cli_chaos.py <intent.md>`
- **"Auto-fix the fragility"** → `verified-rollout/cli_harden.py <intent.md>`
- **"Score the pipeline statistically"** → `dataset/bench/bench_runner.py --judge --n 30`
- **"Has my last config change improved things?"** → `dataset/bench/bench_ab.py --a CFG_A --b CFG_B --n 30`
- **"Auto-improve the pipeline overnight"** → `validation/auto_calibrate.py --auto --apply --commit`
- **"Discover prompt mutations from accumulated bench traces"** → `validation/gepa_optimizer.py --n 20 --holdout-n 12`
- **"Did the model bump under us?"** → `validation/drift_check.py`
- **"Where did each warning come from?"** → `validation/run_log.py` then read `validation/RUN_LOG.md`

## Smoke test

`validation/smoke.sh` runs a 60-second end-to-end check (one tiny
intent through `cli_pro` + judge). Catches regressions; serves as
the "does this still work?" check after a major change.
