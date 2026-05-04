# Bench run — 20260430T143409Z

_Pipeline: `cli_pro`. Sample size: 20. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 1 | 1 | 0 | 0 | 0 | 0 | 0/3 (0%) | 189.7 |
| `swebench_pro` | 1 | 0 | 0 | 1 | 0 | 0 | 1/3 (33%) | 124.7 |
| `swebench_verified` | 2 | 1 | 0 | 1 | 0 | 0 | 6/6 (100%) | 209.2 |
| `synthetic` | 2 | 0 | 0 | 2 | 0 | 0 | 4/6 (67%) | 198.5 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 0 | 0 | 1 | 0 |
| `swebench_pro` | 0 | 1 | 0 | 0 | 0 |
| `swebench_verified` | 0 | 1 | 0 | 1 | 0 |
| `synthetic` | 0 | 1 | 0 | 1 | 0 |

## Overall (literal scorer): caught=2, partial=0, missed=4, error=0, no_GT=0

## Overall (LLM judge)

caught=4, partial=2, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `synthetic/react_17_19/security_hardening/mid_saas/tiny/00001` | missed | partial | Plan matches React 19 cutover, legacy context shim, dual-run, and allowlist/defa |
| `synthetic/elasticsearch_7_8/schema_migration/mid_saas/medium` | missed | caught | It explicitly covers ES8 security/mTLS, index template/mapping changes, reindex/ |
| `swebench_verified/scikit-learn__scikit-learn-10908` | missed | caught | It targets sklearn/feature_extraction/text.py and the exact fitted-state fix: us |
| `swebench_verified/sympy__sympy-18763` | caught | caught | Plan directly targets sympy/printing/latex.py _print_Subs and parentheses around |
| `swebench_pro/instance_internetarchive__openlibrary-30bc73a13` | missed | partial | It matches the cover-archive migration and schema-first rollout, but misses the  |
| `danluu_postmortems/amazon` | caught | caught | Plan explicitly limits the scaling change to a canary/off-peak rollout with hard |