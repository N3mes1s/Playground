# Playground

A brain-dump workspace for experiments, evolved into a working
**multi-stakeholder rollout planning** system for managed coding
agents. Six experiments + a 20k-element evaluation bench + a
self-improving continuous-calibration loop, all on a shared
`mirofish_lab/` substrate (CAMEL-AI agents, structured-constraint
debate, formal verification, chaos analysis).

For the **architecture map and end-to-end pipeline**, see
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

## Quick start

```bash
cp .env.example .env       # OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt
bash validation/smoke.sh   # 60-second end-to-end check
```

## I want to ...

| Goal | Run this |
|---|---|
| Get a rollout plan for a proposed change | [`verified-rollout/cli_pro.py <intent.md>`](./verified-rollout/cli_pro.py) |
| ... with concrete file references against a real repo | [`verified-rollout/cli_grounded.py <intent.md> --repo PATH`](./verified-rollout/cli_grounded.py) |
| Diagnose why a plan is fragile | [`verified-rollout/cli_chaos.py <intent.md>`](./verified-rollout/cli_chaos.py) |
| Auto-fix the fragility | [`verified-rollout/cli_harden.py <intent.md>`](./verified-rollout/cli_harden.py) |
| Rehearse a PR review before opening the PR | [`pr-review-rehearsal/cli.py --pr-url URL`](./pr-review-rehearsal/) |
| Rehearse multiple implementation styles for an issue | [`pre-flight-rehearsal/cli.py --issue-url URL`](./pre-flight-rehearsal/) |
| Predict downstream breakage of a diff | [`blast-radius-prediction/cli.py --pr URL --repo PATH`](./blast-radius-prediction/) |
| Triage findings from a static audit | [`adversarial-security-sim/cli.py REPORT.md`](./adversarial-security-sim/) |
| Score the pipeline statistically | [`dataset/bench/bench_runner.py --judge --n 30`](./dataset/bench/bench_runner.py) |
| Auto-improve the pipeline | [`validation/auto_calibrate.py --auto --apply --commit`](./validation/auto_calibrate.py) |
| Discover prompt mutations from accumulated traces | [`validation/gepa_optimizer.py --n 20 --holdout-n 12`](./validation/gepa_optimizer.py) |

## Six experiments + evaluation layer

| Directory | What it does |
|---|---|
| [`verified-rollout/`](verified-rollout/) | THE ROLLUP. Five CLIs (cli_pro / cli_grounded / cli_chaos / cli_harden / cli_pro again) that combine the substrate into Pareto plans with formal verification, chaos analysis, NSGA-II ranking, and an optional closed-loop hardener. Real-world demos: `simonw/llm` OTel tracing patch, `n3mes1s/claude-teleport-analyzer` SQLite cache, FastAPI/Pydantic v2 migration. |
| [`rollout-rehearsal/`](rollout-rehearsal/) | The 6-stakeholder structured-constraint planner that `verified-rollout` builds on. |
| [`pr-review-rehearsal/`](pr-review-rehearsal/) | Four reviewer personas (security, perf, architect, PM) critique a PR diff in parallel; judge ranks concerns. |
| [`pre-flight-rehearsal/`](pre-flight-rehearsal/) | Four implementer styles produce plans for a GitHub issue; judge picks winner. |
| [`blast-radius-prediction/`](blast-radius-prediction/) | Subsystem-as-persona; predict per-subsystem breakage from a diff. |
| [`adversarial-security-sim/`](adversarial-security-sim/) | RedTeamTriager + Maintainer debate over each finding from a static audit report. |
| [`dataset/`](dataset/) | 20,479-element evaluation corpus (10,479 real + 10,000 synthetic) + bench_runner with LLM-judge scorer. Sources: SWE-Bench (verified + pro + original + multi), danluu/post-mortems, template-based synthetic generator. |
| [`validation/`](validation/) | Continuous-improvement loop: warning detection (`run_log.py`), outcome feedback (`feedback.py`), bench-driven A/B (`ab_harness.py`, `bench_ab.py`), auto-calibrator (`auto_calibrate.py`), GEPA-style autonomous prompt optimisation (`gepa_optimizer.py`), drift detection (`drift_check.py`). Calibration history in `calibrations.jsonl`. |
| [`mirofish_lab/`](mirofish_lab/) | Shared substrate. Personas, agents, simulation primitives, verification (structural + Z3 SMT), chaos analyses (LLM probe + static + adversarial + Monte Carlo), grounding, NSGA-II Pareto. |
| [`recursive-lm-security-audit/`](recursive-lm-security-audit/) | Earlier experiment: DSPy-based static security scanner. Used as a downstream consumer by `adversarial-security-sim`. |
| [`vulnllm-analyzer/`](vulnllm-analyzer/) | Earlier experiment: VulnLLM-R-7B served on Modal GPUs. |
| [`fixtures/`](fixtures/) | Pre-fetched intent / PR / diff fixtures used by experiments without network access. |

## Statistical baseline

The bench has been re-run on a **30-element stratified sample**
across all 5 sources (`swebench_verified`, `swebench_pro`,
`swebench_original`, `danluu_postmortems`, `synthetic`),
judge-scored. Latest measurement (validation/REBASELINE_2026-04-30):

- **useful_rate**: **97%** (29/30; caught + partial)
- **caught_rate**: 33% (10/30; full semantic match with ground truth)
- **missed_rate**: **3%** (1/30; pipeline produced unrelated output)
- **SMT feasibility**: 82% (74/90 plans across 30 elements pass Z3)
- **composite score**: ~0.98

Per-source signal:

- `danluu_postmortems` is strongest (4/6 caught): post-mortem-style
  framing matches the multi-stakeholder pipeline well.
- `swebench_pro` has the lone genuine miss (1/6); the others
  partial-credit the right zone but miss specific files.

That number is what `auto_calibrate` and `gepa_optimizer` improve
against. See [`validation/RUN_LOG.md`](./validation/RUN_LOG.md) for
both the **latest snapshot** section (auto-pulled from the newest
`REBASELINE_*.json` — what the calibrator gates against) and the
all-time aggregate below it (older runs may dominate); see
[`validation/calibrations.jsonl`](./validation/calibrations.jsonl)
for the audit log of every fix proposal and verdict.

### Honest follow-up signal: family bias has flipped

Previous warning was "speed family wins >40%" → triggered the
rebalance + antiparallel + prompt_revision fix sequence. The
re-baseline shows safety family now at 47%, above the same 40%
threshold. The rebalance over-corrected. The symmetric fix
`safety_family_dominance` / `rebalance_safetyward` is now wired
into `auto_calibrate.KNOWN_WARNINGS` (commit `74b595e`); it
reads the latest snapshot section of RUN_LOG and would pull
fragility back up (0.20 → 0.25) if applied.

### Honest follow-up signal: GEPA cycle 4 didn't generalise

Cycle 4 reported `specify-concrete-artifacts` beat the incumbent
by +0.183 composite / +17pp useful on a 6-element eval slice. The
matched **held-out** validation on a disjoint 6-element slice
(`validation/holdout/HOLDOUT_REPORT.md`) found:

- useful_rate 100% / 100% — tied (both hit the ceiling)
- caught_rate 67% / 67% — tied
- composite +0.028 (only just above the 2pp threshold)
- SMT feasibility +5pp (the lone real signal)

The cycle-4 incumbent's 83% useful was an unlucky eval-slice draw,
not a fixable failure mode. The directive isn't harmful and gives a
small SMT-feasibility lift, so `mirofish_lab/pareto_extra.txt` is
retained — but treat the cycle-4 +17pp as eval-slice bias, not a
real headline gain. Next cycle should target SMT or family-bias
where headroom remains, not useful_rate.

## What's NOT here

- A web UI. Markdown reports + JSON sidecars only.
- Production deploys. Plans are advisory; an executor agent
  dispatches them.
- A trained model of our own. We use `gpt-5.4-mini` for everything;
  swap via `MODEL` env var.
- Long-term cost calibration. The Monte Carlo gate-failure-rate
  priors are heuristic; calibration from real outcomes is open.

## Status

Experimental by nature. The defaults have been improving across
~40 commits via the auto-calibration + GEPA loops; treat any output
as advisory, not authoritative. See `ARCHITECTURE.md` for the full
data-flow picture.
