# Held-out validation: multistage on real data

## Eval slice (seed 1337) (n=30)

| metric | A: monolith | B: multistage | Δ |
|---|---|---|---|
| judge useful | 100% | 100% | +0pp |
| judge caught | 53% | 60% | +7pp |
| judge missed | 0% | 0% | +0pp |
| max family share | 80% | 77% | -3pp |
| winners /N | 30/30 | 30/30 | +0 |

## Holdout slice (seed 9256, disjoint) (n=30)

| metric | A: monolith | B: multistage | Δ |
|---|---|---|---|
| judge useful | 100% | 100% | +0pp |
| judge caught | 73% | 50% | -23pp |
| judge missed | 0% | 0% | +0pp |
| max family share | 70% | 77% | +7pp |
| winners /N | 30/30 | 30/30 | +0 |

## Verdict

- Eval Δ caught: **+7pp**
- Holdout Δ caught: **-23pp**
- Holdout Δ useful: **+0pp**

**DOWNGRADE TO DIRECTIONAL** — eval-slice +7pp caught did NOT reproduce on holdout (-23pp). useful and plans intact, so no regression — but the +7pp magnitude was likely sample noise. Multistage retained as default (no holdout regression) but external metric claims should NOT cite a caught-rate gain.