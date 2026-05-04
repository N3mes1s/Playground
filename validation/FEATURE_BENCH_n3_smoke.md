# Feature-planning bench — n=3 (seed 2026)

_Pipeline: cli_feature · prefer=balanced._

## Aggregate verdicts

- literal: {'partial': 1, 'caught': 2} (n=3)
- judge:   {'partial': 1, 'caught': 2}

## Per-feature-kind verdicts

| kind | caught | partial | missed |
|---|---|---|---|
| compliance_audit | 0 | 1 | 0 |
| integration_native | 1 | 0 | 0 |
| mobile_parity | 1 | 0 | 0 |

## Per-element scores

| id | winner | literal | judge | days_band | strat_ok | sec |
|---|---|---|---|---|---|---|
| `feature_synthetic/compliance_audit/fintech/enterprise/36241` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/mobile_parity/b2b_saas/early/39603` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/integration_native/dev_tools/early/78037` | mvp_fast | caught | caught | Y | Y | Y |