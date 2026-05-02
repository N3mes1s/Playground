# Feature GEPA cycle — 20260502T100018Z

_Trace source: `validation/FEATURE_BASELINE_N50_safe.json` (14 mismatch traces)._

## Diagnosis

The Sequencer confuses GT rollout styles: it overuses feature_flag/gradual_rollout for regulated or compliance-heavy launches that should be full_release or beta_program, and misses explicit blocker-based criteria for choosing beta vs GA.

## Scoreboard

| Variant | Score | Useful | Caught | Strat-OK | Family |
|---|---|---|---|---|---|
| incumbent | 1.000 | 100% | 33% | 75% | 75% |
| `compliance-fullrelease-rules` | 1.125 | 100% | 25% | 75% | 50% |
| `regulated-vs-beta-rules` | 1.000 | 100% | 25% | 50% | 50% |

## Held-out validation (n=12, seed=12161)

- Incumbent score 1.042, candidate score 0.917, candidate beats: **NO**

## Verdict

**Eval winner `compliance-fullrelease-rules` REJECTED at holdout** (per cycle-4 discipline). Not applying.