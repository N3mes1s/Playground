# verified-rollout

A unique product layered on top of `rollout-rehearsal` that combines
three cutting-edge research angles none of the incumbents (Greptile,
blast-radius.dev, Cursor multi-agent judging, SagaLLM, Bytebase)
combine for migration planning:

1. **Formal verification** of LLM-generated plans
   ([VeriPlan, arXiv 2502.17898](https://arxiv.org/html/2502.17898v1);
   [LLM+SMT for plans, arXiv 2510.03469](https://arxiv.org/html/2510.03469v1)
   reports F1 96.3% on simplified plan verification): DAG check,
   reachability, gate validity, and blocking-constraint coverage.
2. **Pareto-frontier plan generation**
   ([BAO, arXiv 2602.11351](https://arxiv.org/abs/2602.11351);
   [AI-SearchPlanner, arXiv 2508.20368](https://arxiv.org/html/2508.20368)):
   THREE plans from the same constraint set on a fast-vs-safe trade-off
   — `aggressive`, `balanced`, `conservative`.
3. **Counterfactual chaos probing**
   ([CST, arXiv 2602.20710](https://arxiv.org/abs/2602.20710);
   [OWASP ASI 2026 framework]; Frontiers MAS robustness paper):
   a Chaos agent samples mid-graph steps, asks "if this fails at its
   gate, what cascades?", and aggregates a fragility score per plan.

The combination produces a **scoreboard** ranking the three plans by
fragility / coverage / DAG-validity, plus an automated Pareto-optimal
recommendation with rationale.

## Run

```bash
cp .env.example .env  # OPENAI_API_KEY, MODEL=gpt-5.4-mini
pip install -r requirements.txt
python verified-rollout/cli.py fixtures/intent_sqlite_memory_migration.md
```

Output:
- `verified-rollout/reports/<intent>.md` — markdown with scoreboard,
  three plan tables, three verification reports, three chaos probes.
- `verified-rollout/reports/<intent>.json` — sidecar machine-readable
  bundle of every artifact.

## Pipeline

1. Gather stakeholder constraints (reuses
   `mirofish_lab.rollout.STAKEHOLDER_PERSONAS`).
2. Run **three Sequencer variants in parallel**, each with a different
   optimisation axis:
   - **aggressive**: parallelise where possible, monitor-gates over
     approval-gates, low step count, accept rollback complexity.
   - **balanced**: honour every blocking constraint without inventing
     extras, single safety gate per irreversible step.
   - **conservative**: sequentialise risky paths, soak windows, feature
     flags, single-step rollbacks, accept higher step count.
3. **Verify** each plan structurally (`mirofish_lab.verify`):
   - DAG check via Tarjan SCC
   - Reachability from roots
   - Gate-string well-formedness
   - Blocking-constraint coverage by token-overlap heuristic (≥30% of
     constraint's distinctive tokens must appear somewhere in the plan)
4. **Chaos probe** each plan (`mirofish_lab.chaos`):
   - Sample N mid-graph steps (default 3)
   - For each, ask Chaos agent to predict the cascade if that step
     fails at its gate
   - Aggregate fragility = avg(blocked_downstream / total_downstream),
     avg severity, and rollback-failure rate.
5. **Recommend** the Pareto-optimal plan: minimise fragility, break
   ties by coverage, then step count, then prefer balanced.

## What's actually unique

- **Greptile / CodeRabbit / blast-radius.dev**: code-graph-only impact;
  no plans, no verification, no Pareto, no chaos.
- **Cursor multi-agent judging**: judges *implementations*, not
  rollouts; no formal verification.
- **SagaLLM**: rule-based dependency graph (academic); no Pareto, no
  chaos probe.
- **Bytebase / Liquibase / Argo Rollouts**: execute plans; don't
  generate or verify them.
- **VeriPlan paper**: travel-planning use case; no migration domain,
  no Pareto frontier, no chaos.

The combination — Pareto + verification + counterfactual chaos +
scored auto-recommendation — is, as far as the recent literature
shows, not yet shipped as a product.

## Honest limits

- Verification is structural (DAG / reachability / token-overlap
  coverage), not full LTL/SMT model checking. A future version could
  emit Z3 constraints and run a real solver — implementation in
  `mirofish_lab.verify` is intentionally hookable for that upgrade.
- Chaos probing samples 3 steps per plan by default; small plans get
  proportionally more coverage.
- The recommendation is a single-objective Pareto pick (fragility-
  first); a richer version would surface the full Pareto front and
  let the user pick by their own utility weights.
