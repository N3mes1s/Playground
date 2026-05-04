# Bench run — 20260504T080952Z

_Pipeline: `cli_feature`. Sample size: 30. Seed: 9256._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 15 | 0 | 0 | 13 | 0 | 2 | 45/45 (100%) | 37.8 |
| `swebench_verified` | 15 | 0 | 0 | 15 | 0 | 0 | 45/45 (100%) | 33.5 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 0 | 0 | 0 | 15 |
| `swebench_verified` | 0 | 0 | 0 | 0 | 15 |

## Overall (literal scorer): caught=0, partial=0, missed=28, error=0, no_GT=2

## Overall (LLM judge)

caught=15, partial=15, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `swebench_verified/django__django-11848` | missed | partial | It correctly targets parse_http_date and the RFC 850 two-digit year bug, but giv |
| `swebench_verified/pytest-dev__pytest-7324` | missed | partial | It correctly targets Expression.compile and a non-crashing fix, but gives no fil |
| `swebench_verified/matplotlib__matplotlib-24637` | missed | partial | Captures the AnnotationBbox SVG gid regression, but no file-level evidence or re |
| `danluu_postmortems/browserstack` | no_ground_truth | caught | It directly names the Shellshock-vulnerable prototype machine and secret keys, p |
| `swebench_verified/django__django-14140` | missed | caught | It targets Q.deconstruct, the single-child boolean-expression crash, and preserv |
| `danluu_postmortems/at-t` | missed | caught | Plan directly targets the AT&T failure mode: staggered switch restart, controlle |
| `danluu_postmortems/heroku` | missed | caught | It explicitly catches the FK/PK type-compatibility constraint that caused the da |
| `danluu_postmortems/shapeshift` | no_ground_truth | partial | It captures the need for hardened internal pilot and custody-privileged access c |
| `swebench_verified/django__django-15863` | missed | partial | It correctly targets Decimal precision in floatformat, but gives no file-level o |
| `danluu_postmortems/amazon` | missed | caught | It directly captures the S3 typo-driven server-removal outage and the need for e |
| `danluu_postmortems/homebrew` | missed | caught | It directly captures the GitHub PAT scope leak and the risk of git-push access t |
| `swebench_verified/django__django-14017` | missed | caught | It targets Q/Exists operator commutativity in django/db/models/query_utils.py, m |
| `danluu_postmortems/google` | missed | partial | It captures canary-first rollout and error-rate gating, but misses the specific  |
| `swebench_verified/sympy__sympy-18199` | missed | partial | It correctly identifies the zero-root bug in nthroot_mod and asks for a targeted |
| `swebench_verified/django__django-15098` | missed | partial | It correctly identifies i18n_patterns locale matching for script+region and case |
| `swebench_verified/django__django-15930` | missed | caught | It targets the exact negated empty-IN Case/When crash and names the empty-predic |
| `danluu_postmortems/metrist` | missed | partial | It captures Azure dependency risk and monitored rollout/rollback, but not the un |
| `swebench_verified/pallets__flask-5014` | missed | caught | Plan directly matches GT: add constructor guard in blueprints.py to reject empty |
| `danluu_postmortems/google` | missed | partial | It captures a staged, risk-limited rollout and avoiding combined risky changes,  |
| `danluu_postmortems/cloudflare` | missed | caught | It explicitly targets BGP prefix ordering validation and staged canary rollout,  |
| `danluu_postmortems/parity` | missed | caught | The plan directly captures the Parity bug: a non-UI multisig/core contract chang |
| `swebench_verified/django__django-12262` | missed | partial | It clearly targets template-tag arg handling and error messages, but never names |
| `danluu_postmortems/github` | missed | partial | It reflects a DDoS-mitigation rollout and staged exposure, but misses the GitHub |
| `danluu_postmortems/joyent` | missed | caught | It explicitly flags the key Postgres failure mode: a new global lock in metadata |
| `swebench_verified/django__django-13925` | missed | partial | It correctly identifies W042 false positives on inherited manual PKs, but gives  |
| `danluu_postmortems/cloudflare` | missed | partial | It recognizes a Cloudflare DNS rollout and the need to limit exposure before bro |
| `danluu_postmortems/sentry` | missed | caught | It directly names Postgres txid-wraparound prevention and a gate on transaction  |
| `swebench_verified/django__django-10999` | missed | partial | It correctly targets parse_duration negative-duration parsing with regression te |
| `swebench_verified/pytest-dev__pytest-7432` | missed | caught | It correctly targets skip-location reporting under --runxfail and limits the fix |
| `swebench_verified/django__django-16139` | missed | caught | It matches the GT bug: a minimal fix in django/contrib/auth/forms.py for passwor |