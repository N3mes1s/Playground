# Feature-planning bench — n=20 (seed 1337)

_Pipeline: cli_feature · prefer=balanced._

## Aggregate verdicts

- literal: {'partial': 3, 'caught': 9} (n=12)
- judge:   {'partial': 9, 'caught': 3}

## Per-feature-kind verdicts

| kind | caught | partial | missed |
|---|---|---|---|
| ai_assistant | 1 | 0 | 0 |
| analytics_export | 0 | 1 | 0 |
| billing_metered | 1 | 0 | 0 |
| compliance_audit | 0 | 1 | 0 |
| in_app_notifications | 1 | 0 | 0 |
| integration_native | 1 | 0 | 0 |
| mobile_parity | 1 | 0 | 0 |
| public_api_v2 | 1 | 0 | 0 |
| realtime_collab | 0 | 1 | 0 |
| search_global | 1 | 0 | 0 |
| self_serve_signup | 1 | 0 | 0 |
| sso_oauth | 1 | 0 | 0 |

## Per-element scores

| id | winner | literal | judge | days_band | strat_ok | sec |
|---|---|---|---|---|---|---|
| `feature_synthetic/realtime_collab/healthtech/enterprise/29768` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/integration_native/marketplace/growth/97612` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/search_global/marketplace/early/48720` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/self_serve_signup/healthtech/growth/84959` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/public_api_v2/healthtech/early/76662` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/sso_oauth/b2b_saas/early/41625` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/ai_assistant/healthtech/growth/84344` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/in_app_notifications/marketplace/growth/74354` | robust_launch | caught | partial | Y | Y | Y |
| `feature_synthetic/analytics_export/consumer_app/growth/83737` | robust_launch | partial | partial | Y | Y | Y |
| `feature_synthetic/compliance_audit/marketplace/early/59641` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/mobile_parity/consumer_app/growth/62786` | robust_launch | caught | partial | Y | Y | Y |
| `feature_synthetic/billing_metered/dev_tools/growth/08579` | mvp_fast | caught | partial | Y | Y | Y |