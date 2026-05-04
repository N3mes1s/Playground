# Bench run — 20260504T080124Z

_Pipeline: `cli_feature`. Sample size: 30. Seed: 9256._

## Per-source verdicts

| Source | N | caught | partial | missed | error | no GT | smt feas. | avg time (s) |
|---|---|---|---|---|---|---|---|---|
| `danluu_postmortems` | 15 | 0 | 0 | 13 | 0 | 2 | 45/45 (100%) | 18.5 |
| `swebench_verified` | 15 | 0 | 0 | 15 | 0 | 0 | 45/45 (100%) | 18.6 |

## Winner-family distribution per source

| Source | speed | safety | cost | balanced | other / ? |
|---|---|---|---|---|---|
| `danluu_postmortems` | 0 | 0 | 0 | 0 | 15 |
| `swebench_verified` | 0 | 0 | 0 | 0 | 15 |

## Overall (literal scorer): caught=0, partial=0, missed=28, error=0, no_GT=2

## Overall (LLM judge)

caught=22, partial=8, missed=0, no_GT=0

## Per-element verdicts (literal vs judge)

| Element | literal | judge | judge rationale |
|---|---|---|---|
| `swebench_verified/django__django-11848` | missed | caught | It directly targets parse_http_date’s two-digit year rollover using current-year |
| `swebench_verified/pytest-dev__pytest-7324` | missed | partial | It matches the bugfix goal for Expression.compile(), but the plan is generic and |
| `swebench_verified/matplotlib__matplotlib-24637` | missed | caught | Plan explicitly targets AnnotationBbox gid propagation to SVG output, matching t |
| `danluu_postmortems/browserstack` | no_ground_truth | caught | It explicitly captures the core root cause: legacy prototype machines with secre |
| `swebench_verified/django__django-14140` | missed | caught | Plan targets Q.deconstruct for non-tuple single children with a minimal backward |
| `danluu_postmortems/at-t` | missed | caught | It directly captures the AT&T outage pattern: race/reboot cascade after planned  |
| `danluu_postmortems/heroku` | missed | caught | It directly identifies the core FK-vs-PK data type mismatch and overflow constra |
| `danluu_postmortems/shapeshift` | no_ground_truth | partial | It captures security/risk controls for crypto transfers, but misses the core roo |
| `swebench_verified/django__django-15863` | missed | partial | It identifies floatformat precision loss for Decimal inputs, but only gives gene |
| `danluu_postmortems/amazon` | missed | caught | It directly captures the typo-driven bulk server-removal failure and the need to |
| `danluu_postmortems/homebrew` | missed | caught | It directly captures the GitHub token scope leak and git-push repo-write path in |
| `swebench_verified/django__django-14017` | missed | caught | Plan targets Q/Exists commutativity for & and |, keeps change in operator fallba |
| `danluu_postmortems/google` | missed | caught | It directly reflects the outage domain: BigQuery/Write API streaming, US Multi-R |
| `swebench_verified/sympy__sympy-18199` | missed | caught | It directly targets the nthroot_mod bug of missing x=0 when a % p == 0, matching |
| `swebench_verified/django__django-15098` | missed | partial | It correctly identifies i18n_patterns locale-prefix matching for script+region B |
| `swebench_verified/django__django-15930` | missed | caught | It matches the exact bug class: CASE/WHEN with negated empty IN, narrowly scoped |
| `danluu_postmortems/metrist` | missed | caught | It directly captures the Azure-specific constraint and even blocks rollout on un |
| `swebench_verified/pallets__flask-5014` | missed | caught | It clearly targets rejecting empty Blueprint names and raising ValueError, match |
| `danluu_postmortems/google` | missed | partial | It reflects a Google network rollout with config-drift and East Coast canary/rol |
| `danluu_postmortems/cloudflare` | missed | caught | Plan directly targets BGP prefix ordering and staged rollout, matching Cloudflar |
| `danluu_postmortems/parity` | missed | caught | It directly captures the key Parity failure: a contract-critical change mislabel |
| `swebench_verified/django__django-12262` | missed | partial | It matches the bug class and shared simple_tag/inclusion_tag parser path, but gi |
| `danluu_postmortems/github` | missed | caught | It directly captures the GitHub incident theme and the DDoS resilience constrain |
| `danluu_postmortems/joyent` | missed | caught | It directly captures the PostgreSQL lock failure and the unsafe global-lock quer |
| `swebench_verified/django__django-13925` | missed | partial | It matches the W042 regression on inherited primary keys, but gives no evidence  |
| `danluu_postmortems/cloudflare` | missed | partial | It captures a DNS config rollout with SERVFAIL safeguards, but misses the specif |
| `danluu_postmortems/sentry` | missed | caught | It explicitly captures the Postgres transaction ID wraparound risk and rollout c |
| `swebench_verified/django__django-10999` | missed | caught | It targets parse_duration negative-duration parsing, cites a regression for the  |
| `swebench_verified/pytest-dev__pytest-7432` | missed | caught | Plan targets the exact bug in src/_pytest/skipping.py and keeps skip location st |
| `swebench_verified/django__django-16139` | missed | caught | Plan explicitly targets UserAdmin password help link construction for to_field a |