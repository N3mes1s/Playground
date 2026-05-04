# Bench run — 20260430T045050Z

_Pipeline: `cli_pro`. Sample size: 12. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 3 | 0 | 0 | 3 | 0 | 0 | 8/9 (89%) | 32.7 |
| `swebench_pro` | 3 | 0 | 0 | 3 | 0 | 0 | 9/9 (100%) | 31.8 |
| `swebench_verified` | 3 | 0 | 0 | 3 | 0 | 0 | 6/9 (67%) | 65.1 |
| `synthetic` | 3 | 0 | 0 | 3 | 0 | 0 | 8/9 (89%) | 24.8 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 2 | 1 | 0 | 0 | 0 |
| `swebench_pro` | 2 | 1 | 0 | 0 | 0 |
| `swebench_verified` | 1 | 2 | 0 | 0 | 0 |
| `synthetic` | 3 | 0 | 0 | 0 | 0 |

## Overall (literal scorer): caught=0, partial=0, missed=12, error=0, no_GT=0

## Overall (LLM judge)

caught=4, partial=6, missed=2, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `synthetic/node_16_20/split_monolith/oss_project/large/00001` | missed | partial | It captures a split-monolith migration with backward compatibility and consumer  |
| `swebench_verified/pydata__xarray-4629` | missed | caught | Plan targets merge(combine_attrs='override') attrs aliasing and explicitly says  |
| `swebench_verified/django__django-11095` | missed | caught | It matches the core GT: add a backward-compatible get_inlines hook for admin inl |
| `synthetic/mongodb_5_7/merge_services/regulated_fintech/large` | missed | partial | It captures merge-services rollout mechanics and rollback-per-tenant, but misses |
| `synthetic/react_17_19/api_breaking/small_startup/large/00001` | missed | partial | It reflects versioned endpoints, backward compatibility, and a deprecation windo |
| `swebench_pro/instance_ansible__ansible-622a493ae03bd5e5cf517` | missed | missed | Output is a generic rollout/safety plan with feature flags and maintenance windo |
| `danluu_postmortems/github` | missed | caught | The plan directly targets the GitHub DDoS incident by emphasizing DDoS mitigatio |
| `swebench_pro/instance_flipt-io__flipt-c188284ff0c094a4ee281a` | missed | partial | It captures AWS-chain auth for OCI pulls and backward-compatible static auth, bu |
| `danluu_postmortems/owasa` | missed | caught | Plan directly addresses the config-error root cause: wrong control/button mappin |
| `danluu_postmortems/duo` | missed | partial | It captures the core DB-capacity/queue overload theme, but the actual post-morte |
| `swebench_pro/instance_element-hq__element-web-b007ea81b2ccd0` | missed | missed | Output is a generic safety rollout plan; it չի mention the arrays.ts/Playback.ts |
| `swebench_verified/django__django-11087` | missed | partial | It targets QuerySet.delete()/deletion collector and required fields, matching th |