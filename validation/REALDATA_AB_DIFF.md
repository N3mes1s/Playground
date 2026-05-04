# Real-data A/B at n=27: monolith vs multistage

_SWE-Bench Verified + danluu post-mortems, seed 1337, rollout-style LLM judge (files_touched / root_cause_keywords / outcome)._

## Aggregate metrics

| metric | A: monolith | B: multistage | Δ |
|---|---|---|---|
| judge useful | 100% | 100% | +0pp |
| judge caught ←target | 53% | 60% | +7pp |
| judge missed | 0% | 0% | +0pp |
| SMT feasibility | 100% | 100% | +0pp |
| max family share | 80% | 77% | -3pp |
| winners /N | 30/30 | 30/30 | +0 |

## Winner distribution

| variant | A | B |
|---|---|---|
| `mvp_fast` | 1 | 0 |
| `robust_launch` | 5 | 7 |
| `standard` | 24 | 23 |

## Per-element judge transitions (A → B)

| transition | count |
|---|---|
| caught -> caught | 13 |
| partial -> partial | 9 |
| partial -> caught | 3 |
| caught -> partial | 2 |

## Verdict

**APPLY ON REAL DATA** — judge caught +7pp, useful +0pp. The synthetic-N=48 regression did NOT reproduce on real-data GT — confirms the synthetic dataset's expected_launch_strategy was the bottleneck. Re-instate multistage as default for cli_feature.