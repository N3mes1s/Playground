# Bench dataset — first batch built and exercised

## What's in the corpus

| Source | Count | Provenance |
|---|---|---|
| `swebench_verified` | 500 | HF `princeton-nlp/SWE-bench_Verified` |
| `swebench_pro` | 731 | HF `ScaleAI/SWE-bench_Pro` |
| `swebench_original` | 8,800 | HF `princeton-nlp/SWE-bench` (test+dev+train, capped at 8800) |
| `danluu_postmortems` | 191 | git clone `danluu/post-mortems`, parse README links |
| **Real total** | **10,222** | |
| `synthetic` | 10,000 | template-based generator: 20 tech-stacks × 10 change-types × 5 org-contexts × 5 scale-tiers |
| **Grand total** | **20,222** | |

(Bulk `.jsonl` files are gitignored to keep clones small. A 50-per-source
`dataset/data/SAMPLE.jsonl` is committed for verification. Full
regeneration is one command per source — see "Reproduce" below.)

## What the synthetic generator covers

20 tech stacks (Pydantic v1→v2, Django 4→5, Rails 6→7, Postgres 12→16,
Kubernetes 1.27→1.30, OpenSSL 1.1→3.x, ...), 10 change types (schema
migration, API breaking, dep upgrade, infra cutover, framework swap,
rename refactor, security hardening, feature-flag cleanup, split
monolith, merge services), 5 org contexts (small startup, mid SaaS,
enterprise, regulated fintech, OSS project), 5 scale tiers (tiny →
xlarge from 1k LOC to 10M LOC).

Each synthetic element declares `metadata.expected_stakeholders` as a
weak ground-truth signal: the bench can score "did the pipeline emit
constraints from those stakeholders?"

## Open evaluation benches we drew on

- **SWE-bench / SWE-bench Verified / SWE-bench Pro / Multi-SWE-bench**
  — software-engineering issue → patch benchmarks. Each issue's
  `problem_statement` becomes a rollout intent; each `patch` becomes
  ground-truth `files_touched` + distinctive tokens.
- **danluu/post-mortems** — curated post-mortem link aggregator. Each
  entry becomes a "pre-incident" intent: imagine the rollout that
  would have caused this incident; identify the constraint that
  would have prevented it.

We surveyed but did not yet integrate AgentBench, Multi-SWE-bench
(load failed on first attempt — schema issue, deferred), SWE-bench-Live,
and Memory AgentBench. Adding them is mechanical via the same
`dataset/sources/<name>.py` pattern.

## First bench run (sample of 12 stratified across 4 sources)

Pipeline: `cli_pro` (full Pareto + chaos + SMT verify), 3 plans per
intent, 1200 max tokens. Total LLM cost roughly $0.05.

| Source | N | caught | partial | missed | error | SMT feasibility | avg time |
|---|---|---|---|---|---|---|---|
| `swebench_verified` | 3 | **2** | 0 | 1 | 0 | 6/9 (67%) | 70 s |
| `swebench_pro` | 3 | 0 | 0 | 3 | 0 | 7/9 (78%) | 37 s |
| `danluu_postmortems` | 3 | 0 | 0 | 3 | 0 | **9/9 (100%)** | 23 s |
| `synthetic` | 3 | 0 | 0 | 3 | 0 | 9/9 (100%) | 15 s |
| **overall** | **12** | **2** | 0 | 10 | 0 | 31/36 (86%) | 36 s |

Catch rate: **17%** on this sample. Nothing to celebrate yet — but
this is the first **statistical** number we have for the pipeline,
backed by 20k items of stratified ground truth, replacing the
13-case existence-proof the validation suite delivered before.

### Honest reading

- `swebench_verified` is where the pipeline does best (2/3 caught)
  because its ground truth is a concrete patch, and the cli_pro plan
  text often mentions the right files.
- `swebench_pro` missed all 3 — these are harder, longer-horizon
  enterprise tasks where naming the right file is harder.
- `danluu_postmortems` missed all 3 because the keyword scoring
  matches against tags like `aws`, `cloudflare`, etc.; the plan
  rarely contains those tag-words verbatim.
- `synthetic` missed all 3 because the expected-stakeholders match
  threshold (60%) is currently strict and the cli_pro pipeline
  emits abbreviated owner names.

These are **scoring-metric problems as much as pipeline problems**.
The fix is to relax keyword matching against the post-mortems
(use semantic match, not literal token), and lower the
expected-stakeholders threshold or use weighted overlap. Both are
follow-ups now that the loop is in place.

### Family bias check on this sample

| Source | speed | safety | cost | balanced |
|---|---|---|---|---|
| `danluu_postmortems` | 2 | 1 | 0 | 0 |
| `swebench_pro` | 1 | 2 | 0 | 0 |
| `swebench_verified` | 1 | 1 | 0 | 1 |
| `synthetic` | 3 | 0 | 0 | 0 |

Synthetic intents drive 100% speed-leaning recommendations — same
pattern the meta-analysis earlier flagged. Confirms the rebalanced
defaults still favour speed when the intent is generic. A real signal
that the synthetic-template intents are too vague, OR that the
speed-leaning prompt is too persuasive on under-constrained inputs.

## Reproduce

```bash
# 1. Pull real data
python dataset/sources/swebench_pro.py        # 731 + 500 elements
python dataset/sources/swebench_original.py   # ~8800
python dataset/sources/postmortems.py         # ~191

# 2. Generate synthetic
python dataset/synthetic/generator.py --n 10000

# 3. Run bench (small sample first; scale up later)
OPENAI_API_KEY=... python dataset/bench/bench_runner.py \
    --n 50 \
    --sources swebench_verified swebench_pro danluu_postmortems synthetic \
    --pipeline cli_pro
```

## What's next (open work)

1. **Scale the sample**. 12 elements is a sanity check. A 200-sample
   run is the smallest defensible eval; a 1000-sample run produces
   stable per-source statistics. At ~$0.005/element on
   `gpt-5.4-mini` that's ~$5 for 1000 elements.

2. **Wire bench into auto_calibrate**. Today auto-calibrate uses a
   2-intent A/B; replacing that with `bench_runner.py` on 200+
   stratified elements gives a real statistical signal for whether
   a config change improves things.

3. **Better scoring metrics**.
   - Semantic keyword match (embedding similarity) for post-mortems
     instead of literal token overlap.
   - Weighted expected-stakeholder match for synthetic (partial
     credit per persona).
   - Confidence intervals on caught-rate per source.

4. **Add the missing sources**.
   - Multi-SWE-bench (schema fix needed in loader).
   - SWE-bench-Live (continuously updated).
   - GitHub Issues with `label:migration` / `label:breaking-change`
     across top-200 OSS repos via the GitHub Search API.

5. **Bench → auto-calibrate flywheel**. The full continuous-improvement
   loop becomes:
   - Run bench every PR / nightly on main.
   - `run_log.py` aggregates over historical bench runs.
   - `auto_calibrate.py` reads aggregates, proposes fixes, A/B tests
     against a held-out subsample.
   - Each calibration record is a row in `calibrations.jsonl` linked
     to the bench run that proved it helps.

That's the loop the user asked for. The primitives are all built;
the wiring of bench → auto_calibrate is the last piece.
