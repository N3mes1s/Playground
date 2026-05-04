# Bench run — 20260504T073810Z

_Pipeline: `cli_feature`. Sample size: 30. Seed: 1337._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 15 | 0 | 0 | 13 | 0 | 2 | 45/45 (100%) | 17.0 |
| `swebench_verified` | 15 | 0 | 0 | 15 | 0 | 0 | 45/45 (100%) | 17.6 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 0 | 0 | 0 | 15 |
| `swebench_verified` | 0 | 0 | 0 | 0 | 15 |

## Overall (literal scorer): caught=0, partial=0, missed=28, error=0, no_GT=2

## Overall (LLM judge)

caught=16, partial=14, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `danluu_postmortems/pagerduty` | missed | caught | It directly captures the key constraint: cross-DC independence and quorum safety |
| `danluu_postmortems/cloudflare` | missed | partial | It captures config-safe rollout controls and single-DC canarying, but misses the |
| `swebench_verified/django__django-14140` | missed | partial | It correctly points to Q.deconstruct() and single-child non-tuple handling, but  |
| `swebench_verified/scikit-learn__scikit-learn-14894` | missed | partial | It identifies the sparse SVM empty-support_vectors_ bug, but gives no file-level |
| `swebench_verified/scikit-learn__scikit-learn-10908` | missed | caught | It targets sklearn/feature_extraction/text.py and explicitly fixes get_feature_n |
| `swebench_verified/sphinx-doc__sphinx-10323` | missed | caught | It directly targets literalinclude prepend/append indentation preservation, matc |
| `danluu_postmortems/salesforce` | no_ground_truth | caught | It explicitly guards cross-DC failover on file parity and limits rollout to one  |
| `danluu_postmortems/skyliner` | missed | partial | It captures a safe rollout for a library upgrade, but misses the actual outage c |
| `danluu_postmortems/google` | missed | caught | Plan explicitly stages a controlled livestream-viewer subset and gates GA on QoE |
| `danluu_postmortems/valve` | missed | caught | Plan directly targets BGP rollout risk, major transit reachability, and rollback |
| `swebench_verified/django__django-11880` | missed | caught | Plan targets django/forms/fields.py and explicitly deep-copies shared error_mess |
| `danluu_postmortems/metrist` | missed | caught | The plan directly reflects the Azure-specific root cause by blocking unannounced |
| `swebench_verified/sympy__sympy-12419` | missed | partial | It matches the nested-sum identity-matrix bug and regression focus, but is too g |
| `swebench_verified/django__django-14855` | missed | caught | It targets readonly FK admin links in custom AdminSite and says to change admin  |
| `danluu_postmortems/heroku` | missed | partial | It captures the DB type-compatibility/overflow constraint and impact on auth/dep |
| `danluu_postmortems/cloudflare` | missed | partial | It matches the DNS/SERVFAIL outage theme and phased rollout constraint, but miss |
| `danluu_postmortems/knight-capital` | missed | caught | It directly captures the Knight Capital failure mode: mixed old/new deployed ver |
| `danluu_postmortems/yeller` | no_ground_truth | partial | It captures delayed-message SLA and partition symptom rollback, but misses the l |
| `swebench_verified/django__django-11848` | missed | caught | It targets the exact HTTP date two-digit year bug, limited to django/utils/http. |
| `swebench_verified/django__django-13109` | missed | caught | Matches the core bug: FK existence validation should switch from default to base |
| `swebench_verified/django__django-12050` | missed | partial | It captures the exact regression and regression tests, but not the concrete djan |
| `swebench_verified/django__django-13023` | missed | caught | It names DecimalField.to_python dict inputs and the need to raise ValidationErro |
| `danluu_postmortems/etsy` | missed | caught | It explicitly constrains rollout to switch-configured segments and staged enable |
| `swebench_verified/django__django-12965` | missed | partial | It captures the fast bulk-delete regression and preserving fallback semantics, b |
| `danluu_postmortems/google` | missed | partial | It captures a config rollout with canarying and blast-radius checks, but misses  |
| `danluu_postmortems/stackdriver` | missed | partial | It captures the blocking-ingestion rollout constraint and canary gating, but mis |
| `swebench_verified/sympy__sympy-14248` | missed | caught | It explicitly targets MatrixSymbol subtraction rendering and names the exact pri |
| `swebench_verified/sympy__sympy-20154` | missed | partial | It correctly targets partitions() and stopping reuse of yielded dicts, but lacks |
| `swebench_verified/scikit-learn__scikit-learn-11310` | missed | partial | It captures the new refit_time_ API on search CV estimators, but lacks the concr |
| `danluu_postmortems/heroku` | missed | caught | It directly targets the Heroku failure mode: remote config rollout, incomplete p |