# Pipeline run log — meta-analysis

_14 eligible runs across `validation/` and `verified-rollout/reports/`._

## Bias check: winner family distribution

| Family | Wins |
|---|---|
| speed | 6 (43%) ⚠️ over 40% |
| safety | 4 (29%) |
| cost | 3 (21%) |
| balanced | 1 (7%) |

If any one family wins >40%, the recommendation logic likely has a bias and the utility weights / preset defaults should be reviewed.

## SMT feasibility rate

- Plans across all runs: **59**
- SMT-feasible: **24** (41%)
- A low feasibility rate (<50%) suggests the Sequencer is producing ordering contradictions; review the constraint-mapping heuristics.

## Winner fragility distribution

- Average winner fragility: **0.397**
- If average winner fragility is below ~0.20, the recommender is plausibly over-weighting cascade-fragility (which rewards parallelism) at the expense of operationally-safer sequential plans.

## Per-run summary

| Run | Winner | Plans | SMT feas. | Winner fragility |
|---|---|---|---|---|
| `validation/grounded_demo/REPORT.json` | 01-safety-leaning | 4 | 1/4 | 0.447 |
| `validation/postmortems/reports/02_cloudflare_mcp_rollout.pro.json` | 02-speed-leaning | 4 | 1/4 | 0.091 |
| `validation/postmortems/reports/01_atlassian_app_deletion.pro.json` | 03-safety-tilted | 4 | 0/4 | 0.533 |
| `validation/postmortems/reports/03_cloudflare_dc_failover.pro.json` | 00-cost-leaning | 4 | 0/4 | 0.618 |
| `validation/postmortems/reports/05_linear_cascade_migration.pro.json` | 03-safety-tilted | 4 | 0/4 | 0.545 |
| `validation/postmortems/reports/04_gitlab_db_replica.pro.json` | 00-cost-leaning | 4 | 4/4 | 0.5 |
| `validation/real_world_demo/cli_pro.json` | 02-speed-leaning | 6 | 0/6 | 0.071 |
| `validation/real_world_demo/teleport_cache.grounded.json` | 02-speed-leaning | 4 | 4/4 | 0.436 |
| `validation/real_world_demo/teleport_cache.safety.json` | 02-speed-leaning | 4 | 3/4 | 0.4 |
| `validation/real_world_demo/teleport_cache.balanced.json` | 00-cost-leaning | 4 | 4/4 | 0.4 |
| `validation/real_world_demo/llm_otel.grounded.json` | 02-speed-leaning | 4 | 2/4 | 0.339 |
| `validation/real_world_demo/teleport_cache.speed.json` | 03-safety-tilted | 4 | 2/4 | 0.433 |
| `verified-rollout/reports/intent_sqlite_memory_migration.pro.json` | 04-speed-tilted | 6 | 3/6 | 0.071 |
| `verified-rollout/reports/intent_sqlite_memory_migration.json` | balanced | 3 | 0/3 | 0.667 |