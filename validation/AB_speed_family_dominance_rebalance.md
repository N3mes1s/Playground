# A/B harness: `baseline` vs `candidate_rebalance`

_Generated 2026-04-30T04:21:32Z_

Criterion: **balanced**

## Summary

| Metric | A: `baseline` | B: `candidate_rebalance` | Δ (B − A) |
|---|---|---|---|
| n runs | 2.00 | 2.00 | +0.00 |
| max winner-family share | 50.00% | 50.00% | +0.00% |
| SMT feasibility rate | 25.00% | 25.00% | +0.00% |
| avg winner fragility | 0.54 | 0.84 | +0.30 |
| median winner fragility | 0.54 | 0.84 | +0.30 |
| winner fragility p90 | 0.69 | 1.00 | +0.31 |

## Verdict

**A better** — composite score A=-0.794 → B=-1.094

## Per-intent

| Intent | A winner | A frag | B winner | B frag |
|---|---|---|---|---|
| `04_gitlab_db_replica.md` | 01-safety-leaning | 0.4 | 03-safety-tilted | 0.688 |
| `05_linear_cascade_migration.md` | 00-cost-leaning | 0.688 | 00-cost-leaning | 1.0 |

## Family distributions

| Family | A count | B count |
|---|---|---|
| cost | 1 | 1 |
| safety | 1 | 1 |