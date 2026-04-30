# Continuous improvement loop

The pipeline's recommendation quality is not fixed-on-build; it depends
on prompts, metric weights, persona definitions, and many other
choices that drift as the world (and the LLM) change. Three
components close that loop:

```
              ┌────────────────────────────────────────────────┐
              │                                                │
              │   1. RUNS                                      │
              │   cli_grounded / cli_pro / cli_chaos / cli_harden  │
              │                                                │
              │   each invocation appends a JSON sidecar       │
              │                                                │
              └──────────────────┬─────────────────────────────┘
                                 │
                                 ▼
              ┌────────────────────────────────────────────────┐
              │                                                │
              │   2. META-ANALYSIS  (run_log.py)               │
              │   - winner-family distribution                 │
              │   - SMT feasibility rate                       │
              │   - avg winner fragility                       │
              │   - 40%-bias warning, <50%-feasibility warning │
              │                                                │
              └──────────────────┬─────────────────────────────┘
                                 │
                                 ▼
              ┌────────────────────────────────────────────────┐
              │                                                │
              │   3. OUTCOME FEEDBACK  (feedback.py)           │
              │   record:                                      │
              │   - was the winner actually followed?          │
              │   - which gates fired in production?           │
              │   - which constraints turned out wrong/useful? │
              │   - actual_recovery_class                      │
              │                                                │
              └──────────────────┬─────────────────────────────┘
                                 │
                                 ▼
              ┌────────────────────────────────────────────────┐
              │                                                │
              │   4. CALIBRATION                               │
              │   informed by the above:                       │
              │   - rebalance UtilityWeights defaults          │
              │   - retune persona prompts (drop owners that   │
              │     get flagged-wrong repeatedly)              │
              │   - adjust MC failure-rate priors with real    │
              │     gate-violation data                        │
              │   - tighten search-pattern templates           │
              │                                                │
              └─────────┬──────────────────────────────────────┘
                        │
                        └────► back to 1
```

## What's already in place

### 1. Run log of every invocation

Every cli_grounded / cli_pro / cli_chaos / cli_harden writes a JSON
sidecar next to its markdown report. Today these accumulate under:

- `validation/{postmortems,swebench,real_world_demo,grounded_demo,...}/`
- `verified-rollout/reports/`

The shape is stable enough that `run_log.py` can mechanically scan
all of them and aggregate.

### 2. Meta-analysis: `validation/run_log.py`

```bash
python validation/run_log.py
```

Writes `validation/RUN_LOG.md` with:

- **Winner-family distribution**. Counts how often each Pareto label
  family (`speed*`, `safety*`, `cost*`, `balanced`) wins across all
  runs. Warns if any family exceeds 40%.
- **SMT feasibility rate**. Plans that pass Z3 verification across
  all runs. Warns if below 50%.
- **Average winner fragility**. Warns if below 0.20 (suggests
  parallelism bias in the recommender).
- **Per-run summary table**.

The latest run of this tool (after the rebalance + `--prefer` fix)
flagged TWO structural issues that had been invisible:

> ⚠️ speed family wins 6/14 (43%, over the 40% threshold)
> ⚠️ SMT feasibility 24/59 (41%, below the 50% threshold)

Both findings are real, and were not visible without the meta-pass.

### 3. Outcome feedback: `validation/feedback.py`

When a real plan from a real run is actually executed (or rejected),
the operator records the outcome:

```bash
python validation/feedback.py record \
    --run validation/real_world_demo/teleport_cache.balanced.json \
    --winner-was-followed yes \
    --actual-outcome success \
    --gate-violations "S5: monitor:err<0.1% threshold breached during canary" \
    --constraint-was-wrong "DataPlatform's wait_for:secrets_rotation was not actually blocking" \
    --constraint-was-useful "Security's 0600 file permission constraint" \
    --notes "actually shipped; cache-hit logging worked first try"

python validation/feedback.py summary
```

`feedback.jsonl` is the persistent record. The summary subcommand
aggregates which **stakeholder personas get flagged wrong most
often** — a direct signal that a persona's system prompt needs
revision.

### 4. Bias-fix knobs already in the pipeline

After the speed-leaning bias was identified:

- **Default `UtilityWeights` rebalanced** in `mirofish_lab/pareto_frontier.py`:
  - `fragility` 0.40 → 0.20
  - `rollback_failure` 0.05 → 0.25
  - others unchanged
- **`UtilityWeights.preset()`** with named presets (`safety`, `speed`,
  `cost`, `balanced`).
- **`cli_grounded.py --prefer {safety,speed,cost,balanced}`** flag
  selects a preset; or `--utility "fragility=0.4,..."` for custom
  weights.
- **Per-plan rationale section** in the markdown report shows utility
  scores for ALL plans, not just the winner — so the human can spot
  ties or near-ties and override.

Re-running the same intent (the `claude-teleport-analyzer` SQLite
cache one) under different presets demonstrates the recommendation
actually shifts:

| Preset | Winner | Why |
|---|---|---|
| `--prefer safety` | 02-speed-leaning | barely (3-way tie at -0.13) |
| `--prefer speed` | 03-safety-tilted | because it had the lowest fragility 0.379 on this intent |
| `--prefer balanced` | 00-cost-leaning | new default actually picks differently than the old fragility-dominated default |

The old behaviour (always 02-speed-leaning) is broken; the new
behaviour shifts based on user preference and per-intent metrics.

## What's NOT yet in place (next iteration)

1. **Automatic recalibration**. Today, if `feedback.py summary`
   reveals BackendOwner constraints are flagged wrong 80% of the
   time, a human has to read the report and manually edit the
   persona prompt. A future version could:
   - Re-run the persona prompt through a "self-critic" LLM,
   - Compare to feedback patterns,
   - Propose a revised prompt as a PR.

2. **MC prior calibration from real gate-violation data**. The
   per-gate failure-rate priors in `chaos_montecarlo.py` are
   heuristic. Once `feedback.py` accumulates 50+ records of actual
   `gate_violations`, we can replace the heuristic table with a
   Beta-prior + observed counts.

3. **A/B harness for prompt changes**. When we change a persona's
   system prompt or a Sequencer's bias lines, we currently have no
   way to know if it helps or hurts. A future tool runs the full
   suite of validation intents under both versions and compares
   recommendations / SMT-feasibility / fragility distributions.

4. **Automated bias detection**. `run_log.py` currently warns when
   one family wins >40%. A richer version would flag:
   - one persona contributing constraints that are routinely the
     least-cited by Sequencers (suggesting noise),
   - one Achilles-heel pattern recurring across unrelated intents
     (suggesting a prompt fix in `chaos.py`),
   - one search pattern from the SearchPlanner that finds zero
     matches across runs (dead pattern).

5. **Cross-version stability tests**. When the underlying LLM model
   bumps (gpt-5.4-mini → gpt-5.5-mini), the entire recommendation
   surface may shift. A test suite re-runs N reference intents and
   reports drift as a `before/after` table.

## How to actually use this loop

1. **Every run produces a sidecar.** Don't disable.
2. **Periodically run `python validation/run_log.py`**. After a
   batch of new runs, read `validation/RUN_LOG.md`. Act on warnings.
3. **Record outcomes for real runs** that actually got executed
   (the simonw/llm OTel diff is the first such case in this repo).
4. **Tune presets / prompts** when feedback aggregates clearly
   point at a structural issue.
5. **Commit the calibration**. Treat default-weight changes,
   persona-prompt edits, and prior-table updates as first-class
   changes with their own commits and rationale, not silent tweaks.

This is the difference between a tool that produces a fixed
recommendation and a tool whose recommendations get more useful
the more it's used.
