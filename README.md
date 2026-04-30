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

The bench has been run, judge-scored, on a 15-element stratified
sample of the 20k corpus. Incumbent (current defaults) score:

- **useful_rate**: 93% (caught + partial)
- **composite score**: 0.880

That number is what `auto_calibrate` and `gepa_optimizer` improve
against. See [`validation/RUN_LOG.md`](./validation/RUN_LOG.md) for
the latest cross-run aggregation and active warnings; see
[`validation/calibrations.jsonl`](./validation/calibrations.jsonl)
for the audit log of every fix proposal and verdict.

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
