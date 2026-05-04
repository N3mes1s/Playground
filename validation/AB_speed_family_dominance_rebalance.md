# Bench-driven A/B — 2026-04-30T05:06:06Z

Sample size per config: **6**. Sources: ['swebench_verified', 'danluu_postmortems', 'synthetic']. Criterion: **useful_rate**.

## Configs

- **A**: `fragility=0.2,coverage=0.25,steps=0.1,severity=0.2,rollback_failure=0.25`
- **B**: `fragility=0.15,coverage=0.25,steps=0.1,severity=0.2,rollback_failure=0.3`

## Aggregate verdict

**B better** — useful (caught+partial) rate A=83% → B=100%

## Metrics A vs B

| Metric | A | B | Δ (B − A) |
|---|---|---|---|
| caught rate | 50.0% | 50.0% | +0.0% |
| partial rate | 33.3% | 50.0% | +16.7% |
| missed rate | 16.7% | 0.0% | -16.7% |
| useful (caught+partial) rate | 83.3% | 100.0% | +16.7% |
| SMT feasibility rate | 77.8% | 88.9% | +11.1% |
| max family share | 50.0% | 50.0% | +0.0% |

## Per-element verdicts

| Element | A verdict | B verdict |
|---|---|---|
| `synthetic/k8s_1_27_1_30/schema_migration/oss_project/tiny/00` | partial | partial |
| `swebench_verified/django__django-11880` | caught | caught |
| `synthetic/postgres_12_16/framework_swap/enterprise/xlarge/00` | partial | partial |
| `swebench_verified/sympy__sympy-12419` | missed | partial |
| `danluu_postmortems/metrist` | caught | caught |
| `danluu_postmortems/skyliner` | caught | caught |