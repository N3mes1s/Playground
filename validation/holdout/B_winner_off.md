# Bench run — 20260430T143639Z

_Pipeline: `cli_pro`. Sample size: 20. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 1 | 1 | 0 | 0 | 0 | 0 | 1/3 (33%) | 206.9 |
| `swebench_pro` | 1 | 0 | 0 | 1 | 0 | 0 | 1/3 (33%) | 226.2 |
| `swebench_verified` | 2 | 2 | 0 | 0 | 0 | 0 | 6/6 (100%) | 214.0 |
| `synthetic` | 2 | 0 | 0 | 2 | 0 | 0 | 2/6 (33%) | 208.9 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 1 | 0 | 0 | 0 |
| `swebench_pro` | 0 | 0 | 0 | 1 | 0 |
| `swebench_verified` | 1 | 0 | 0 | 1 | 0 |
| `synthetic` | 0 | 1 | 0 | 1 | 0 |

## Overall (literal scorer): caught=3, partial=0, missed=3, error=0, no_GT=0

## Overall (LLM judge)

caught=4, partial=2, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `synthetic/react_17_19/security_hardening/mid_saas/tiny/00001` | missed | partial | It captures the React 19 cutover with legacy context and concurrent-default test |
| `synthetic/elasticsearch_7_8/schema_migration/mid_saas/medium` | missed | caught | Plan explicitly covers ES7→ES8 compatibility, new mappings, backfill/dual-write, |
| `swebench_verified/scikit-learn__scikit-learn-10908` | caught | caught | Plan directly targets CountVectorizer.get_feature_names, explicit vocabulary pre |
| `swebench_verified/sympy__sympy-18763` | caught | caught | Plan targets sympy/printing/latex.py and the Subs LaTeX parenthesizing bug, matc |
| `swebench_pro/instance_internetarchive__openlibrary-30bc73a13` | missed | caught | Plan matches the core patch: coverstore schema/status tracking, zip batch archiv |
| `danluu_postmortems/amazon` | caught | partial | It captures the AWS capacity-scaling automation causing cross-network congestion |