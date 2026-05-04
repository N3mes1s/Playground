# Bench run — 20260504T074449Z

_Pipeline: `cli_feature`. Sample size: 30. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 15 | 0 | 0 | 13 | 0 | 2 | 45/45 (100%) | 30.0 |
| `swebench_verified` | 15 | 0 | 0 | 15 | 0 | 0 | 45/45 (100%) | 31.2 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 0 | 0 | 0 | 15 |
| `swebench_verified` | 0 | 0 | 0 | 0 | 15 |

## Overall (literal scorer): caught=0, partial=0, missed=28, error=0, no_GT=2

## Overall (LLM judge)

caught=18, partial=12, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `danluu_postmortems/pagerduty` | missed | caught | It names the core outage constraint: two deployments shared an unstated network  |
| `danluu_postmortems/cloudflare` | missed | caught | It clearly targets Cloudflare-style config-error outage prevention via typo chec |
| `swebench_verified/django__django-14140` | missed | partial | It matches the Q.deconstruct single-child crash and backward-compatibility note, |
| `swebench_verified/scikit-learn__scikit-learn-14894` | missed | partial | It matches the sparse SVM empty-support_vectors_ bug and empty dual_coef_ behavi |
| `swebench_verified/scikit-learn__scikit-learn-10908` | missed | partial | It matches the bug: get_feature_names should work when vocabulary is preseeded a |
| `swebench_verified/sphinx-doc__sphinx-10323` | missed | caught | Plan explicitly preserves literalinclude prepend/append indentation and limited  |
| `danluu_postmortems/salesforce` | no_ground_truth | caught | It captures the key Salesforce constraint: do not proceed with cross-DC failover |
| `danluu_postmortems/skyliner` | missed | partial | It reflects an outage and memory-leak rollout gate, but lacks the key third-part |
| `danluu_postmortems/google` | missed | partial | It captures the small-cohort, soak, and QoE-threshold rollout constraints, but t |
| `danluu_postmortems/valve` | missed | caught | It explicitly targets BGP config rollout with canary staging and dual review, ma |
| `swebench_verified/django__django-11880` | missed | caught | It explicitly targets django/forms/fields.py and the deepcopy of error_messages, |
| `danluu_postmortems/metrist` | missed | caught | It directly captures Azure as the root constraint and the need to block public b |
| `swebench_verified/sympy__sympy-12419` | missed | partial | It captures the nested matrix-sum bug and fix scope, but lacks the key sympy/mat |
| `swebench_verified/django__django-14855` | missed | caught | Plan explicitly targets readonly FK admin links under custom AdminSite and scope |
| `danluu_postmortems/heroku` | missed | caught | Plan directly targets the key-size mismatch/overflow causing auth and deployment |
| `danluu_postmortems/cloudflare` | missed | partial | It matches a Cloudflare DNS outage with canary/rollback rollout constraints, but |
| `danluu_postmortems/knight-capital` | missed | caught | It directly names the core Knight Capital failure modes: conflicting versions, r |
| `danluu_postmortems/yeller` | no_ground_truth | partial | It captures delayed-message risk and partition symptoms, but misses the likely r |
| `swebench_verified/django__django-11848` | missed | caught | Plan explicitly targets parse_http_date two-digit rfc850 year logic and boundary |
| `swebench_verified/django__django-13109` | missed | partial | It names FK validation using base manager vs default manager and mentions custom |
| `swebench_verified/django__django-12050` | missed | partial | Captures the regression and preserving list input type, but gives no concrete fi |
| `swebench_verified/django__django-13023` | missed | caught | Plan explicitly targets DecimalField.to_python dict input, changing it to Valida |
| `danluu_postmortems/etsy` | missed | caught | Plan explicitly targets multicast rollout with switch-readiness and narrow pilot |
| `swebench_verified/django__django-12965` | missed | partial | It captures the delete() SQL regression and MySQL/MariaDB lock-table compatibili |
| `danluu_postmortems/google` | missed | partial | It captures a config rollout affecting blob lookup and metadata storage, but mis |
| `danluu_postmortems/stackdriver` | missed | caught | It directly captures the outage root cause and the key constraint: ingestion mus |
| `swebench_verified/sympy__sympy-14248` | missed | caught | Plan explicitly targets MatrixSymbol subtraction printing in str/pretty/latex, m |
| `swebench_verified/sympy__sympy-20154` | missed | caught | It targets sympy.utilities.iterables.partitions(), explicitly removing dict reus |
| `swebench_verified/scikit-learn__scikit-learn-11310` | missed | caught | Plan explicitly adds BaseSearchCV refit_time_ only after best-model refit and no |
| `danluu_postmortems/heroku` | missed | caught | Plan directly targets incomplete config propagation and web dyno start failures, |