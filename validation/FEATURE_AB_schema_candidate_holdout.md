# Feature-planning bench — n=20 (seed 9256)

_Pipeline: cli_feature · prefer=balanced._

## Aggregate verdicts

- literal: {'partial': 5, 'caught': 7} (n=12)
- judge:   {'partial': 8, 'caught': 4}

## Per-feature-kind verdicts

| kind | caught | partial | missed |
|---|---|---|---|
| ai_assistant | 1 | 0 | 0 |
| analytics_export | 0 | 1 | 0 |
| billing_metered | 1 | 0 | 0 |
| compliance_audit | 0 | 1 | 0 |
| in_app_notifications | 0 | 1 | 0 |
| integration_native | 1 | 0 | 0 |
| mobile_parity | 0 | 1 | 0 |
| public_api_v2 | 0 | 1 | 0 |
| realtime_collab | 1 | 0 | 0 |
| search_global | 1 | 0 | 0 |
| self_serve_signup | 1 | 0 | 0 |
| sso_oauth | 1 | 0 | 0 |

## Per-element scores

| id | winner | literal | judge | days_band | strat_ok | sec |
|---|---|---|---|---|---|---|
| `feature_synthetic/compliance_audit/consumer_app/early/05111` | mvp_fast | partial | partial | Y | N | N |
| `feature_synthetic/in_app_notifications/healthtech/early/03939` | robust_launch | partial | caught | N | Y | Y |
| `feature_synthetic/analytics_export/healthtech/early/14726` | mvp_fast | partial | partial | Y | Y | Y |
| `feature_synthetic/integration_native/dev_tools/early/78037` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/search_global/dev_tools/growth/00227` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/mobile_parity/healthtech/early/58422` | mvp_fast | partial | caught | Y | N | Y |
| `feature_synthetic/realtime_collab/fintech/growth/27393` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/b2b_saas/enterprise/49017` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/ai_assistant/healthtech/early/10237` | robust_launch | caught | partial | Y | Y | Y |
| `feature_synthetic/sso_oauth/healthtech/enterprise/82862` | robust_launch | caught | partial | Y | Y | Y |
| `feature_synthetic/self_serve_signup/fintech/enterprise/70105` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/billing_metered/healthtech/early/17060` | mvp_fast | caught | partial | Y | Y | Y |