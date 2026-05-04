# Synthesis A/B at N=48: monolith vs multistage

_Same 48 matched elements (seed 1337). A: pre-A1 monolith baseline (FEATURE_BASELINE_N50_safe.json). B: 4-stage multistage pipeline (commit be1c118 + later)._

## Aggregate metrics

| metric | A: monolith | B: multistage | Δ |
|---|---|---|---|
| judge useful | 100% | 83% | -17pp |
| judge caught ←target | 40% | 17% | -23pp |
| literal caught | 56% | 19% | -38pp |
| strat_ok | 71% | 25% | -46pp |
| sec compliance | 100% | 85% | -15pp |
| days_in_band | 96% | 81% | -15pp |
| max family share | 58% | 40% | -19pp |
| winners /48 | 48 | 41 | -7 |

## Winner distribution

| variant | A | B |
|---|---|---|
| `mvp_fast` | 18 | 14 |
| `robust_launch` | 2 | 8 |
| `standard` | 28 | 19 |

## Per-element judge-verdict transitions (A → B)

| transition | count |
|---|---|
| partial -> partial | 21 |
| caught -> partial | 11 |
| caught -> ? | 4 |
| partial -> caught | 4 |
| caught -> caught | 4 |
| partial -> ? | 3 |
| partial -> missed | 1 |

## Cycle gate verdict

**REVERT** — multistage regresses: useful_rate dropped -17pp (>5pp); 7 more plans broke entirely. Same shape as cycle-2 retrospective. Default reverts to monolith.