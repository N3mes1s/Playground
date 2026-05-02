# Feature-planning bench — n=50 (seed 1337)

_Pipeline: cli_feature · prefer=balanced._

## Aggregate verdicts

- literal: {'caught': 25, 'partial': 23} (n=48)
- judge:   {'partial': 30, 'caught': 18}

## Per-feature-kind verdicts

| kind | caught | partial | missed |
|---|---|---|---|
| ai_assistant | 1 | 3 | 0 |
| analytics_export | 0 | 4 | 0 |
| billing_metered | 4 | 0 | 0 |
| compliance_audit | 0 | 4 | 0 |
| in_app_notifications | 4 | 0 | 0 |
| integration_native | 3 | 1 | 0 |
| mobile_parity | 1 | 3 | 0 |
| public_api_v2 | 1 | 3 | 0 |
| realtime_collab | 1 | 3 | 0 |
| search_global | 4 | 0 | 0 |
| self_serve_signup | 4 | 0 | 0 |
| sso_oauth | 2 | 2 | 0 |

## Per-element scores

| id | winner | literal | judge | days_band | strat_ok | sec |
|---|---|---|---|---|---|---|
| `feature_synthetic/billing_metered/dev_tools/growth/08579` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/self_serve_signup/fintech/early/09275` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/b2b_saas/enterprise/49017` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/integration_native/consumer_app/enterprise/36156` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/mobile_parity/dev_tools/early/71113` | mvp_fast | partial | caught | Y | N | Y |
| `feature_synthetic/in_app_notifications/b2b_saas/growth/64143` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/analytics_export/consumer_app/growth/83737` | standard | partial | partial | Y | Y | Y |
| `feature_synthetic/ai_assistant/healthtech/early/10237` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/integration_native/dev_tools/enterprise/33283` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/compliance_audit/marketplace/early/59641` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/analytics_export/healthtech/enterprise/36105` | mvp_fast | partial | caught | Y | Y | Y |
| `feature_synthetic/search_global/marketplace/early/48720` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/healthtech/early/76662` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/analytics_export/dev_tools/enterprise/56032` | mvp_fast | partial | partial | Y | Y | Y |
| `feature_synthetic/sso_oauth/fintech/growth/75377` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/integration_native/marketplace/growth/97612` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/mobile_parity/consumer_app/early/26998` | mvp_fast | partial | caught | Y | N | N |
| `feature_synthetic/mobile_parity/consumer_app/growth/62786` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/compliance_audit/consumer_app/growth/44435` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/ai_assistant/b2b_saas/early/96092` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/sso_oauth/dev_tools/enterprise/28765` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/realtime_collab/healthtech/enterprise/29768` | mvp_fast | partial | caught | N | Y | Y |
| `feature_synthetic/in_app_notifications/marketplace/growth/74354` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/search_global/healthtech/early/15766` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/public_api_v2/dev_tools/early/39688` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/public_api_v2/consumer_app/enterprise/42737` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/billing_metered/marketplace/growth/66918` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/ai_assistant/consumer_app/early/64920` | mvp_fast | partial | partial | Y | Y | N |
| `feature_synthetic/ai_assistant/healthtech/growth/84344` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/integration_native/consumer_app/early/63910` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/realtime_collab/marketplace/enterprise/80422` | standard | partial | partial | Y | N | Y |
| `feature_synthetic/compliance_audit/fintech/early/54098` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/search_global/marketplace/enterprise/26361` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/self_serve_signup/marketplace/growth/87114` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/realtime_collab/consumer_app/enterprise/37295` | mvp_fast | partial | partial | N | Y | Y |
| `feature_synthetic/in_app_notifications/marketplace/enterprise/28619` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/billing_metered/marketplace/enterprise/48875` | standard | caught | partial | Y | Y | Y |
| `feature_synthetic/search_global/b2b_saas/growth/27293` | standard | caught | caught | Y | Y | Y |
| `feature_synthetic/self_serve_signup/consumer_app/growth/21977` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/in_app_notifications/consumer_app/enterprise/94145` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/sso_oauth/b2b_saas/growth/34671` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/self_serve_signup/healthtech/growth/84959` | mvp_fast | caught | caught | Y | Y | Y |
| `feature_synthetic/analytics_export/marketplace/enterprise/93027` | standard | partial | caught | Y | Y | Y |
| `feature_synthetic/sso_oauth/b2b_saas/early/41625` | mvp_fast | partial | caught | Y | N | Y |
| `feature_synthetic/realtime_collab/healthtech/growth/80021` | mvp_fast | caught | partial | Y | Y | Y |
| `feature_synthetic/compliance_audit/dev_tools/enterprise/35409` | mvp_fast | partial | partial | Y | N | N |
| `feature_synthetic/mobile_parity/fintech/enterprise/59941` | mvp_fast | partial | partial | Y | N | Y |
| `feature_synthetic/billing_metered/consumer_app/growth/32750` | standard | caught | caught | Y | Y | Y |