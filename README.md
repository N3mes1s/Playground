# Playground

## Overview

This repository serves as a **brain dump** for experiments and exploratory projects. It's designed as a sandbox environment where ideas can be tested, prototyped, and iterated upon without the constraints of production requirements.

## Purpose

This is primarily a workspace for **coding agents** to experiment with:
- New coding patterns and techniques
- Proof-of-concept implementations
- Algorithm explorations
- Technology evaluations
- Learning experiments
- Rapid prototyping

## Philosophy

The focus here is on **experimentation and learning** rather than production-ready code. Don't expect everything to be polished or following strict standards - this is where ideas come to life, evolve, and sometimes fail. That's exactly the point.

## Contributing

While this is primarily a coding agent workspace, contributions and suggestions are welcome. Feel free to:
- Open issues for experiment ideas
- Submit pull requests with interesting findings
- Share feedback on experiments

## Experiments

| Directory | Description |
|-----------|-------------|
| [`vulnllm-analyzer/`](vulnllm-analyzer/) | Automated vulnerability analysis for GitHub repos using [VulnLLM-R-7B](https://github.com/ucsb-mlsec/VulnLLM-R) on Modal GPUs |
| [recursive-lm-security-audit](./recursive-lm-security-audit/) | Automated codebase security scanner using DSPy's Recursive Language Model (RLM) module. Accepts a GitHub repo URL or local path and produces a vulnerability report for ~$0.87. |
| [`pr-review-rehearsal/`](pr-review-rehearsal/) | Rehearse a PR review **before** opening the PR. Four reviewer personas debate the diff, an implementer iterates, a judge ranks concerns. |
| [`pre-flight-rehearsal/`](pre-flight-rehearsal/) | Run four implementer styles (Minimalist, Defensive, TestFirst, RefactorHappy) in parallel against a real GitHub issue; a judge picks a winning plan. |
| [`adversarial-security-sim/`](adversarial-security-sim/) | Triage findings from an existing audit report by running an Attacker-vs-Defender debate per finding, judged for `REAL` / `FALSE_POSITIVE` / `NEEDS_VALIDATION`. |
| [`blast-radius-prediction/`](blast-radius-prediction/) | Predict downstream breakage of a diff by treating each top-level subsystem of the repo as an agent with a persona, then simulating their reactions. |
| [`rollout-rehearsal/`](rollout-rehearsal/) | Multi-stakeholder rollout planner: six stakeholder personas (BackendOwner, DataPlatform, SRE, Security, ProductPM, ConsumerSubsystem) emit structured constraints; a Sequencer agent synthesises them into a partial-order plan with explicit gate / rollback / observability per step, plus flagged conflicts and open questions. Targets the migration-ordering gap left by Greptile / blast-radius.dev / Cursor multi-agent judging. |
| [`verified-rollout/`](verified-rollout/) | Layered on rollout-rehearsal: generates THREE Pareto-frontier plans (aggressive / balanced / conservative) from the same constraints, formally verifies each (DAG, reachability, gate validity, blocking-constraint coverage), counterfactually probes each with a Chaos agent for cascade fragility, then recommends the Pareto-optimal plan. Combines VeriPlan-style verification, BAO-style Pareto frontier, and CST-style counterfactual simulation — a combination not yet shipped by any incumbent. |

### Shared scaffold

The four experiments above share [`mirofish_lab/`](mirofish_lab/) — a small,
inspectable substrate built on **CAMEL-AI** (the same engine MiroFish runs
on internally) plus a local JSONL-backed memory layer in place of Zep
Cloud. See `.env.example` for required keys (`OPENAI_API_KEY`, `MODEL`).
All four experiments run end-to-end against real inputs (GitHub PRs/issues,
local repos, existing audit reports) and produce real markdown reports.

## Note

Code in this repository is experimental by nature. Use at your own discretion and don't expect production-level stability or support.
