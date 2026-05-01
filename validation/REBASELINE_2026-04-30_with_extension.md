# Bench run — 20260501T065032Z

_Pipeline: `cli_pro`. Sample size: 30. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 6 | 0 | 0 | 5 | 0 | 1 | 15/18 (83%) | 29.6 |
| `swebench_original` | 6 | 0 | 0 | 6 | 0 | 0 | 16/18 (89%) | 69.7 |
| `swebench_pro` | 6 | 0 | 1 | 5 | 0 | 0 | 13/18 (72%) | 68.8 |
| `swebench_verified` | 6 | 3 | 0 | 3 | 0 | 0 | 12/18 (67%) | 86.2 |
| `synthetic` | 6 | 0 | 0 | 6 | 0 | 0 | 18/18 (100%) | 17.2 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 4 | 2 | 0 | 0 | 0 |
| `swebench_original` | 5 | 1 | 0 | 0 | 0 |
| `swebench_pro` | 3 | 2 | 0 | 1 | 0 |
| `swebench_verified` | 2 | 3 | 0 | 1 | 0 |
| `synthetic` | 6 | 0 | 0 | 0 | 0 |

## Overall (literal scorer): caught=3, partial=1, missed=25, error=0, no_GT=1

## Overall (LLM judge)

caught=6, partial=20, missed=4, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `swebench_verified/django__django-12663` | missed | partial | It matches the SimpleLazyObject queryset RHS coercion regression, but not the co |
| `swebench_verified/django__django-12193` | caught | caught | Directly identifies django/forms/widgets.py and the attrs/checked mutation in Ch |
| `synthetic/go_1_20_1_23/infra_cutover/mid_saas/small/00001` | missed | partial | It captures infra cutover concerns like dual-run, DNS/traffic shift, and backwar |
| `synthetic/go_1_20_1_23/framework_swap/regulated_fintech/larg` | missed | partial | It captures backend compatibility/rollback themes, but misses the Go 1.20→1.23 s |
| `swebench_verified/django__django-15467` | caught | caught | Touches django/contrib/admin/options.py and explicitly preserves custom empty_la |
| `swebench_original/matplotlib__matplotlib-23476` | missed | partial | It matches the pickle/unpickle DPI inflation on MacOSX, but misses the specific  |
| `swebench_original/PrefectHQ__prefect-3085` | missed | partial | It clearly targets DaskExecutor checkpoint/result writes and flows.checkpointing |
| `swebench_pro/instance_flipt-io__flipt-f808b4dd6e36b9dc8b011e` | missed | missed | It only gives generic migration ops advice; it misses the actual config/DB crede |
| `swebench_verified/scikit-learn__scikit-learn-13496` | caught | partial | It matches the core fix: exposing warm_start in IsolationForest, updating docs,  |
| `swebench_pro/instance_ansible__ansible-e0c91af45fa9af575d10f` | partial | partial | Correctly targets lib/ansible/plugins/lookup/env.py and direct os.environ.get()  |
| `synthetic/python_310_312/feature_flag_consolidation/regulate` | missed | partial | It captures feature-flag cleanup and 3.12 runtime concerns, but misses the key P |
| `synthetic/mongodb_5_7/split_monolith/small_startup/small/000` | missed | partial | It captures a generic split-monolith dual-write/backfill migration, but misses t |
| `swebench_original/pydata__xarray-6135` | missed | partial | It captures the float-shift feature and backward-compatible int behavior, but mi |
| `swebench_pro/instance_flipt-io__flipt-292fdaca9be39e6a921aaa` | missed | partial | Captures the core version-field/default/reject behavior, but misses the concrete |
| `swebench_pro/instance_protonmail__webclients-815695401137dac` | missed | missed | Plan is a generic rollout/compatibility strategy; it never names the chunk utili |
| `danluu_postmortems/cloudflare` | missed | caught | It explicitly targets BGP prefix-order rollout, canarying one DC before all 19 d |
| `swebench_original/scikit-learn__scikit-learn-10306` | missed | partial | It correctly targets FastICA/Birch warning-class fixes, but misses most canonica |
| `danluu_postmortems/browserstack` | no_ground_truth | caught | Plan directly targets the Shellshock-vulnerable prototype host and the secret-ke |
| `danluu_postmortems/amazon` | missed | caught | It directly names the ELB production state data maintenance mistake and the need |
| `swebench_verified/django__django-15503` | missed | partial | It matches the JSONField numeric-key lookup bug and adds tests, but lacks the co |
| `swebench_pro/instance_ansible__ansible-189fcb37f973f0b1d52b5` | missed | missed | The plan is a generic backend/data rollout; it never mentions the NIOS module or |
| `swebench_original/Qiskit__qiskit-7733` | missed | partial | It captures the optional-dependency/removal intent, but not the actual Qiskit fi |
| `synthetic/mysql_5_8/api_breaking/regulated_fintech/medium/00` | missed | partial | It captures versioned endpoints, backward compatibility, and SDK regen, but miss |
| `danluu_postmortems/webkit-code-repository` | missed | caught | Plan directly addresses SHA-1 collision/dedup conflict risk by gating collision- |
| `danluu_postmortems/amazon` | missed | partial | It captures generator/PLC phase-check and backup power failover, but misses the  |
| `swebench_verified/django__django-14771` | missed | partial | It matches the reload/xoptions issue and mentions child-process spawn logic, but |
| `synthetic/redis_5_7/schema_migration/enterprise/xlarge/00002` | missed | partial | It captures Redis 7 migration with RESP2/dual-write/backfill/drop-old-later, but |
| `danluu_postmortems/google` | missed | partial | It captures a latent infra-feature rollout behind canary for a Google FE/LB inci |
| `swebench_pro/instance_tutao__tutanota-fe240cbf7f0fdd6744ef7b` | missed | missed | Plan is generic rollout/safety guidance and never mentions calendar date validat |
| `swebench_original/pytest-dev__pytest-6186` | missed | partial | It captures the core junit_family deprecation warning when unset and preserving  |