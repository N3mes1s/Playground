# Bench run — 20260430T124101Z

_Pipeline: `cli_pro`. Sample size: 30. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 6 | 0 | 0 | 5 | 0 | 1 | 12/18 (67%) | 87.7 |
| `swebench_original` | 6 | 0 | 0 | 6 | 0 | 0 | 17/18 (94%) | 95.0 |
| `swebench_pro` | 6 | 0 | 0 | 6 | 0 | 0 | 11/18 (61%) | 109.4 |
| `swebench_verified` | 6 | 0 | 0 | 6 | 0 | 0 | 16/18 (89%) | 101.8 |
| `synthetic` | 6 | 0 | 0 | 6 | 0 | 0 | 18/18 (100%) | 21.4 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 3 | 3 | 0 | 0 | 0 |
| `swebench_original` | 1 | 3 | 0 | 2 | 0 |
| `swebench_pro` | 1 | 3 | 0 | 2 | 0 |
| `swebench_verified` | 0 | 5 | 0 | 1 | 0 |
| `synthetic` | 6 | 0 | 0 | 0 | 0 |

## Overall (literal scorer): caught=0, partial=0, missed=29, error=0, no_GT=1

## Overall (LLM judge)

caught=10, partial=19, missed=1, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `swebench_verified/django__django-12663` | missed | caught | Plan targets django/db/models/sql/query.py lookup prep for SimpleLazyObject RHS  |
| `swebench_verified/django__django-12193` | missed | caught | Plan targets the widget attrs mutation bug and explicitly references checked att |
| `synthetic/go_1_20_1_23/infra_cutover/mid_saas/small/00001` | missed | partial | It captures the Go 1.20/1.23 cutover and parallel traffic window, but misses the |
| `synthetic/go_1_20_1_23/framework_swap/regulated_fintech/larg` | missed | partial | It captures adapter shims and dual-run/parity, but misses the key Go 1.20→1.23 s |
| `swebench_verified/django__django-15467` | missed | caught | It directly captures the core bug: preserve custom empty_label while keeping the |
| `swebench_original/matplotlib__matplotlib-23476` | missed | partial | It correctly targets unpickle-time figure-state handling and preserving old pick |
| `swebench_original/PrefectHQ__prefect-3085` | missed | partial | It captures Dask result-writing and checkpoint config propagation, but misses th |
| `swebench_pro/instance_flipt-io__flipt-f808b4dd6e36b9dc8b011e` | missed | missed | The plan is generic migration ops; it never addresses Flipt config/db URL-vs-spl |
| `swebench_verified/scikit-learn__scikit-learn-13496` | missed | partial | It captures adding warm_start to IsolationForest and repeated-fit tree growth, b |
| `swebench_pro/instance_ansible__ansible-e0c91af45fa9af575d10f` | missed | caught | It explicitly targets env lookup to return raw os.environ values, preserve order |
| `synthetic/python_310_312/feature_flag_consolidation/regulate` | missed | partial | It captures rollout/rollback and backward-compatibility, but misses the core Pyt |
| `synthetic/mongodb_5_7/split_monolith/small_startup/small/000` | missed | partial | It captures backend/data rollout themes like dual-write, traffic mirroring, and  |
| `swebench_original/pydata__xarray-6135` | missed | partial | It matches the feature intent and calendar/frequency constraints, but not the ac |
| `swebench_pro/instance_flipt-io__flipt-292fdaca9be39e6a921aaa` | missed | caught | Plan directly matches the issue: optional config version, default missing to 1.0 |
| `swebench_pro/instance_protonmail__webclients-815695401137dac` | missed | caught | Plan explicitly extracts the chunk utility to a dedicated module and updates the |
| `danluu_postmortems/cloudflare` | missed | caught | Plan directly targets the BGP disabled-prefix ordering bug and limits rollout by |
| `swebench_original/scikit-learn__scikit-learn-10306` | missed | partial | It captures the warning-class migration theme, but not the specific scikit-learn |
| `danluu_postmortems/browserstack` | no_ground_truth | caught | It directly captures the core root cause: a Shellshock-vulnerable prototype host |
| `danluu_postmortems/amazon` | missed | caught | It directly names the core failure: maintenance was run against production ELB s |
| `swebench_verified/django__django-15503` | missed | partial | It identifies the correct JSONField numeric-key bug on SQLite/MySQL/Oracle and p |
| `swebench_pro/instance_ansible__ansible-189fcb37f973f0b1d52b5` | missed | partial | It clearly targets Infoblox fixed-address support and idempotent create/update/d |
| `swebench_original/Qiskit__qiskit-7733` | missed | partial | It correctly captures making python-constraint optional and guarding csplayout i |
| `synthetic/mysql_5_8/api_breaking/regulated_fintech/medium/00` | missed | partial | It captures versioned endpoints, backward compatibility, SDK regen, and auth-plu |
| `danluu_postmortems/webkit-code-repository` | missed | partial | It captures the SHA-1 collision/dedupe/repo-checkout theme, but misses the key c |
| `danluu_postmortems/amazon` | missed | caught | It explicitly targets the failed generator phase-check/PLC path and backup-gener |
| `swebench_verified/django__django-14771` | missed | partial | It matches the reloader/startup area and preserving child-process flags, but nev |
| `synthetic/redis_5_7/schema_migration/enterprise/xlarge/00002` | missed | partial | It matches dual-write/backfill/rollback-style migration mechanics, but misses th |
| `danluu_postmortems/google` | missed | partial | It matches the broad root cause: a new infra feature with staged canary/dual-pat |
| `swebench_pro/instance_tutao__tutanota-fe240cbf7f0fdd6744ef7b` | missed | partial | It captures the core validation issue for calendar create/import and preserving  |
| `swebench_original/pytest-dev__pytest-6186` | missed | partial | It correctly targets a warning-only change around junit XML/default behavior, bu |