# Feature-planning bench — n=50 (seed 1337)

_Pipeline: cli_feature · prefer=balanced._

## Aggregate verdicts

- literal: {'partial': 14, 'caught': 22} (n=36)
- judge:   {'caught': 8, 'partial': 27, 'missed': 1}

## Per-feature-kind verdicts

| kind | caught | partial | missed |
|---|---|---|---|
| ai_assistant | 2 | 0 | 0 |
| analytics_export | 0 | 4 | 0 |
| billing_metered | 1 | 2 | 0 |
| compliance_audit | 0 | 4 | 0 |
| in_app_notifications | 2 | 0 | 0 |
| integration_native | 3 | 0 | 0 |
| mobile_parity | 3 | 1 | 0 |
| public_api_v2 | 3 | 1 | 0 |
| realtime_collab | 0 | 2 | 0 |
| search_global | 2 | 0 | 0 |
| self_serve_signup | 2 | 0 | 0 |
| sso_oauth | 4 | 0 | 0 |

## Per-element scores

| id | winner | literal | judge | days_band | strat_ok | sec |
|---|---|---|---|---|---|---|
| `feature_synthetic/billing_metered/dev_tools/growth/08579` | mvp_fast | partial | caught | Y | Y | N |
| `feature_synthetic/self_serve_signup/fintech/early/09275` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/public_api_v2/b2b_saas/enterprise/49017` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/integration_native/consumer_app/enterprise/36156` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/mobile_parity/dev_tools/early/71113` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/in_app_notifications/b2b_saas/growth/64143` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/analytics_export/consumer_app/growth/83737` | standard | partial | partial | Y | Y | Y |
| `feature_synthetic/ai_assistant/healthtech/early/10237` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/integration_native/dev_tools/enterprise/33283` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/compliance_audit/marketplace/early/59641` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/analytics_export/healthtech/enterprise/36105` | mvp_fast | partial | partial | Y | Y | Y |
| `feature_synthetic/search_global/marketplace/early/48720` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/healthtech/early/76662` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/analytics_export/dev_tools/enterprise/56032` | mvp_fast | partial | partial | Y | Y | Y |
| `feature_synthetic/sso_oauth/fintech/growth/75377` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/integration_native/marketplace/growth/97612` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/mobile_parity/consumer_app/early/26998` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/mobile_parity/consumer_app/growth/62786` | mvp_fast | partial | caught | Y | N | Y |
| `feature_synthetic/compliance_audit/consumer_app/growth/44435` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/ai_assistant/b2b_saas/early/96092` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/sso_oauth/dev_tools/enterprise/28765` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/realtime_collab/healthtech/enterprise/29768` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/in_app_notifications/marketplace/growth/74354` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/search_global/healthtech/early/15766` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/dev_tools/early/39688` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/consumer_app/enterprise/42737` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/billing_metered/marketplace/growth/66918` | standard | partial | partial | Y | Y | Y |
| `feature_synthetic/ai_assistant/consumer_app/early/64920` | — | ERROR | — | — | — | — |
| `feature_synthetic/ai_assistant/healthtech/growth/84344` | — | ERROR | — | — | — | — |
| `feature_synthetic/integration_native/consumer_app/early/63910` | — | ERROR | — | — | — | — |
| `feature_synthetic/realtime_collab/marketplace/enterprise/80422` | — | ERROR | — | — | — | — |
| `feature_synthetic/compliance_audit/fintech/early/54098` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/search_global/marketplace/enterprise/26361` | — | ERROR | — | — | — | — |
| `feature_synthetic/self_serve_signup/marketplace/growth/87114` | — | ERROR | — | — | — | — |
| `feature_synthetic/realtime_collab/consumer_app/enterprise/37295` | — | ERROR | — | — | — | — |
| `feature_synthetic/in_app_notifications/marketplace/enterprise/28619` | — | ERROR | — | — | — | — |
| `feature_synthetic/billing_metered/marketplace/enterprise/48875` | — | ERROR | — | — | — | — |
| `feature_synthetic/search_global/b2b_saas/growth/27293` | — | ERROR | — | — | — | — |
| `feature_synthetic/self_serve_signup/consumer_app/growth/21977` | — | ERROR | — | — | — | — |
| `feature_synthetic/in_app_notifications/consumer_app/enterprise/94145` | — | ERROR | — | — | — | — |
| `feature_synthetic/sso_oauth/b2b_saas/growth/34671` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/self_serve_signup/healthtech/growth/84959` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/analytics_export/marketplace/enterprise/93027` | robust_launch | partial | partial | Y | Y | Y |
| `feature_synthetic/sso_oauth/b2b_saas/early/41625` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/realtime_collab/healthtech/growth/80021` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/compliance_audit/dev_tools/enterprise/35409` | mvp_fast | partial | partial | Y | N | N |
| `feature_synthetic/mobile_parity/fintech/enterprise/59941` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/billing_metered/consumer_app/growth/32750` | standard | caught | missed | Y | Y | Y |