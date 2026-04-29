# Verified Rollout (PRO) — intent_acme_pydantic_v2

> Intent: validation/real_world_demo/intent_acme_pydantic_v2.md · N plans: 6 · Pareto-front size: 4 · Recommendation: 02-speed-leaning · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T22:13:04Z_

## Recommendation

**02-speed-leaning** — rank-0 (Pareto-optimal), utility 0.122 under user weights.

## Pareto frontier (NSGA-II)

_6 plans, 4 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | ∞ | 0.07 | 1.00 | 10 | 2.07 | 0.93 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | ∞ | 0.06 | 1.00 | 12 | 1.94 | 0.94 |
| 04-speed-tilted | 0.50/0.00/0.50 | 0 | ∞ | 0.94 | 1.00 | 12 | 3.50 | 0.31 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | 2.89 | 0.67 | 1.00 | 12 | 2.13 | 0.40 |
| 00-cost-leaning | 0.00/0.00/1.00 | 1 | ∞ | 0.75 | 1.00 | 12 | 2.75 | 0.44 |
| 05-speed-tilted | 0.50/0.50/0.00 | 1 | ∞ | 0.93 | 1.00 | 12 | 3.33 | 0.40 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
*                                       *     .           .*
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*                                                           
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.06, 0.94]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Audit current schemas/validators/encoders and classify breaking vs compatibility | Backend | — | `none` | discard audit notes and reopen the assessment |
| S2 | Send partner/integrator notices and assign a named customer-escalation owner for | ProductPM | S1 | `approval:customer_escalation_owner` | withdraw notices and reschedule communications |
| S3 | Complete security review for Pydantic v2 validation changes and rotate any secre | Security | S1 | `approval:security` | restore previous secret versions and defer the migration |
| S4 | Run bump-pydantic, upgrade FastAPI/Pydantic versions, convert orm_mode to from_a | Backend | S2, S3 | `none` | revert the branch to the pre-migration dependency and code s |
| S5 | Build and run compatibility tests against current traffic fixtures, focusing on  | Backend | S4 | `wait_for:compatibility_tests_pass` | revert incompatible model changes and retry tests |
| S6 | Publish the exact v2 OpenAPI artifact and regenerate @acme/payments-client@2.x p | DataPlatform | S5 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S7 | Get mobile apps into a release-ready state and complete app-store submission so  | Mobile | S6 | `wait_for:mobile SDK shipped and in user hands` | pull the submission and keep shipping the prior SDK |
| S8 | Coordinate internal consumer rollout of @acme/payments-client@2.x while keeping  | ConsumerSubsystem | S6 | `monitor:internal_client_v2_adoption>=80%` | revert affected consumers to @acme/payments-client@1.x |
| S9 | Enable the server-side v2 compatibility path behind a feature flag, keeping dual | SRE | S5, S6, S7, S8 | `none` | disable the v2 schema/serialization flag and serve v1-compat |
| S10 | Deploy the new server build in a business-hours canary and keep traffic small wh | SRE | S9 | `window:business-hours excluding Friday afternoon and incident windows` | shift traffic back to FastAPI 0.95.2 + Pydantic v1 deploymen |
| S11 | If canary stays within baseline, expand rollout to production while preserving t | SRE | S10 | `monitor:validation_rejection_rate<=0.1% above baseline` | revert server to backward-compatible schema and keep v1 clie |
| S12 | After 80% internal adoption and mobile release are confirmed, schedule the depre | Backend | S11 | `wait_for:80% internal client migration and mobile SDK release in user hands` | restore v1-compatible request/response handling |

## SMT verification: 00-cost-leaning

- backend: `z3` (12 steps, 15 dep edges, 5 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S6` depends_on `S5` (so `S5` must be earlier)
- BackendOwner's blocking constraint requires `S6` before `S5` (gate `wait_for:compatibility_tests_pass`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.75
- **fragility curve**: budget=1 → 0.857, budget=2 → 0.0
- **avg severity**: 2.75 (1=low … 4=critical)
- **rollback-failure rate**: 0.438 (7/16 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=4, redo_full=3
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S8` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | NO | — | manual_ops |
| S11 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | redo_full |
| S2 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | redo_full |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | redo_full |
| S6, S7 | gate_violation | medium | NO | — | manual_ops |
| S2, S6 | gate_violation | medium | NO | — | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Create a migration branch and inventory all Pydantic/FastAPI touchpoints: valida | Backend | — | `none` | delete migration branch and revert inventory notes |
| S2 | Run bump-pydantic codemod across the codebase, then manually rewrite the 6 root  | Backend | S1 | `none` | revert codemod changes and restore pre-migration model code |
| S3 | Replace remaining .dict()/.json() usage with .model_dump()/.model_dump_json(), t | Backend | S2 | `none` | restore prior dump calls and compatibility shims from versio |
| S4 | Refactor the two tax-service validators to remove async-in-validator behavior by | Backend | S2 | `wait_for:secret_rotation_complete` | restore previous secret version and revert validator-path re |
| S5 | Run baseline traffic characterization on v1 for the strict-coercion-sensitive en | DataPlatform | S2 | `monitor:validation_rejection_rate<=0.1% increase` | disable new validation path and redeploy_previous |
| S6 | Regenerate OpenAPI from the v2 code, review schema diffs, publish the signed-off | DataPlatform | S3, S5 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S7 | Publish @acme/payments-client@2.x and release the updated mobile SDKs to app sto | ProductPM | S6 | `wait_for:client_v2_published_and_mobile_sdk_released` | revert client publish and mobile SDK release artifacts |
| S8 | Send partner/integrator notices and release-manager approvals for the upcoming m | ProductPM | S6 | `window:partner_notice_14d` | revert docs/client publish and redeploy_previous |
| S9 | Deploy the FastAPI 0.110 + Pydantic v2 server behind a feature flag that preserv | SRE | S4, S6, S8 | `approval:security` | disable the v2 schema/serialization flag and serve v1-compat |
| S10 | Run business-hours canary rollout with staged traffic increase, holding the depl | SRE | S9 | `window:business-hours excluding Friday afternoon and incident windows` | shift traffic back to FastAPI 0.95.2 + Pydantic v1 deploymen |
| S11 | Maintain dual-support for v1 and v2 clients in production, with the compatibilit | ConsumerSubsystem | S7, S9 | `monitor:internal_client_v2_adoption>=80%` | restore v1-compatible request/response handling |
| S12 | After 80% internal adoption and mobile SDKs are in user hands, remove the legacy | Backend | S11 | `wait_for:30_day_quiet_period_with_no_legacy_field_usage` | restore legacy fields and backfill missing values |

## SMT verification: 01-safety-leaning

- backend: `z3` (12 steps, 15 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S9` depends_on `S4` (so `S4` must be earlier)
- BackendOwner's blocking constraint requires `S9` before `S4` (gate `wait_for:compatibility_tests_pass`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.667
- **fragility curve**: budget=1 → 0.769, budget=2 → 0.0
- **avg severity**: 2.13 (1=low … 4=critical)
- **rollback-failure rate**: 0.4 (6/15 probes)
- **recovery distribution**: recoverable_in_window=3, manual_ops=11, redo_full=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S5` → 1.0
  - `S7` → 1.0
  - `S8` → 1.0
  - `S3` → 0.5

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | low | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S9, S10, S11, S12 | manual_ops |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | manual_ops |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | manual_ops |
| S7 | gate_violation | high | yes | S9, S10, S11, S12 | manual_ops |
| S8 | gate_violation | medium | yes | S9, S10, S11, S12 | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S11 | gate_violation | medium | yes | S12 | manual_ops |
| S1 | rollback_failure | medium | NO | S2, S3, S4, S5, S6, S7 | redo_full |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S11, S2 | gate_violation | medium | NO | — | manual_ops |
| S6, S4 | gate_violation | medium | NO | — | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Run the FastAPI/Pydantic migration codemods across the codebase, then manually r | Backend | — | `none` | revert the migration branch and restore the last v1-compatib |
| S2 | Manually review and patch the two async tax-service validators, then rotate any  | Security | S1 | `wait_for:secret_rotation_complete` | restore previous secret version and revert validator changes |
| S3 | Run compatibility and regression tests against the v2 codebase, focusing on requ | Backend | S1, S2 | `wait_for:compatibility_tests_pass` | revert to the last passing v1-compatible branch |
| S4 | Generate the exact v2 OpenAPI artifact from the reviewed code and publish it for | DataPlatform | S3 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw v2 artifacts and republish the v1 artifacts |
| S5 | Regenerate and publish @acme/payments-client@2.x, then regenerate the mobile SDK | Platform | S4 | `wait_for:client_v2_published_and_mobile_sdk_released` | withdraw v2 client/mobile artifacts and republish the prior  |
| S6 | Send partner/integrator notices and customer escalation ownership for the coming | Product | S4 | `window:partner_notice_14d` | retract notices only if no external distribution occurred; o |
| S7 | Run internal consumer migration and mobile rollout tracking until the new client | ConsumerSubsystem | S5, S6 | `wait_for:mobile SDK shipped and in user hands` | keep v1 client support and pause any v1 deprecation work |
| S8 | Enable the server-side v2 compatibility flag in canary, keeping dual-support for | SRE | S3, S5, S6, S7 | `monitor:validation_rejection_rate<=0.1% above baseline` | disable the v2 schema/serialization flag and serve v1-compat |
| S9 | Expand staged rollout during the safe production window while keeping legacy com | SRE | S8 | `window:business-hours excluding Friday afternoon and incident windows` | pause rollout and keep current production version serving tr |
| S10 | After sustained baseline performance, deprecate v1-only paths and keep the dual- | Backend | S9 | `monitor:internal_client_v2_adoption>=80%` | restore v1-compatible request/response handling |

## SMT verification: 02-speed-leaning

- backend: `z3` (10 steps, 14 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S5` depends_on `S4` (so `S4` must be earlier)
- DataPlatform's blocking constraint requires `S5` before `S4` (gate `wait_for:published_openapi_v2_and_signed_off_schema_diff`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.071
- **fragility curve**: budget=1 → 0.083, budget=2 → 0.0
- **avg severity**: 2.07 (1=low … 4=critical)
- **rollback-failure rate**: 0.929 (13/14 probes)
- **recovery distribution**: manual_ops=14
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 0.5
  - `S2` → 0.0
  - `S3` → 0.0
  - `S4` → 0.0
  - `S5` → 0.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | gate_violation | medium | NO | — | manual_ops |
| S3 | gate_violation | medium | NO | — | manual_ops |
| S4 | gate_violation | medium | NO | — | manual_ops |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S9, S6 | gate_violation | medium | NO | — | manual_ops |
| S8, S9 | gate_violation | medium | NO | — | manual_ops |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Inventory all v1-only Pydantic usage, flag the 2 tax-service validator endpoints | Backend | — | `none` | discard analysis artifacts and restore previous migration no |
| S2 | Apply bump-pydantic codemod across the repo, then manually rewrite 6 root valida | Backend | S1 | `none` | revert codemod commit and manual edits |
| S3 | Refactor the 2 async tax-service validators into sync-safe paths with explicit s | Backend | S2 | `wait_for:secret_rotation_complete` | restore previous validator implementation and previous secre |
| S4 | Add compatibility shims and explicit non-strict relaxations for fields that regr | Backend | S2, S3 | `monitor:validation_rejection_rate<=0.1% above baseline` | disable the v2 validation path and serve v1-compatible handl |
| S5 | Run the full v2 test suite, including compatibility tests for all payment endpoi | Backend | S4 | `wait_for:compatibility_tests_pass` | revert to the last green migration commit |
| S6 | Generate the exact v2 OpenAPI artifact from the tested code, publish it, and sig | DataPlatform | S5 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S7 | Regenerate and publish @acme/payments-client@2.x from the exact v2 schema, then  | ConsumerSubsystem | S6 | `none` | unpublish v2 client artifacts and restore v1 client publishi |
| S8 | Update docs.acme.internal/payments to reflect the v2 schema and new client major | ProductPM | S6 | `window:after-committed_partner_notice_lead_time` | revert docs to the v1-compatible version |
| S9 | Send partner and integrator notices covering the v2 client, docs changes, and an | ProductPM | S7, S8 | `approval:release_manager` | retract the notice and pause downstream rollout |
| S10 | Ship the new mobile SDK through app store release channels and wait until it is  | Mobile | S7, S9 | `wait_for:mobile SDK shipped and in user hands` | halt server cutover and keep mobile on the old SDK path |
| S11 | Enable the v2 compatibility flag for a small canary slice in production, keeping | SRE | S5, S9, S10 | `window:business-hours excluding Friday afternoon and incident windows` | disable the v2 schema/serialization flag and serve v1-compat |
| S12 | Expand production rollout only if canary metrics stay within baseline, while pre | SRE | S11 | `monitor:validation_rejection_rate<=0.1% above baseline` | shift traffic back to FastAPI 0.95.2 + Pydantic v1 deploymen |

## SMT verification: 03-safety-tilted

- backend: `z3` (12 steps, 16 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- DataPlatform's blocking constraint requires `S7` before `S6` (gate `wait_for:published_openapi_v2_and_signed_off_schema_diff`)
- step `S7` depends_on `S6` (so `S6` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.062
- **fragility curve**: budget=1 → 0.071, budget=2 → 0.0
- **avg severity**: 1.94 (1=low … 4=critical)
- **rollback-failure rate**: 0.938 (15/16 probes)
- **recovery distribution**: recoverable_in_window=1, manual_ops=15
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 0.5
  - `S2` → 0.0
  - `S3` → 0.0
  - `S4` → 0.0
  - `S5` → 0.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | low | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | NO | — | manual_ops |
| S3 | gate_violation | medium | NO | — | manual_ops |
| S4 | gate_violation | medium | NO | — | manual_ops |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S10 | gate_violation | medium | NO | — | manual_ops |
| S11 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S8, S9 | gate_violation | medium | NO | — | manual_ops |
| S8, S5 | gate_violation | medium | NO | — | manual_ops |

## Plan: 04-speed-tilted (weights (0.5, 0.0, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Run secret rotation for the two tax-service validator endpoints and freeze rollo | Security + SRE | — | `window:business-hours excluding Friday afternoon and incident windows` | restore previous secret version and pause rollout |
| S2 | Execute bump-pydantic across the codebase, then manually rewrite 6 root validato | Backend | S1 | `none` | redeploy_previous |
| S3 | Rewrite the two remote-tax-service validator paths into sync-safe logic, explici | Backend | S2 | `none` | redeploy_previous |
| S4 | Run compatibility, regression, and schema-diff test suites against the v2 codepa | Backend + Security + DataPlatform | S2, S3 | `wait_for:compatibility_tests_pass` | redeploy_previous |
| S5 | Generate the OpenAPI artifact from the exact v2 schema, review and sign off the  | DataPlatform | S4 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S6 | Regenerate and publish @acme/payments-client@2.x from the signed-off v2 OpenAPI, | SDK Release + Mobile | S5 | `wait_for:client_v2_published_and_mobile_sdk_released` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S7 | Send partner-integrator notice and customer-facing communications covering schem | ProductPM | S5 | `wait_for:partner-integrator-notice-sent` | revert docs/client publish and redeploy_previous |
| S8 | Update the documentation site to reflect the v2 schema and new client guidance,  | ProductPM + Docs | S5, S7 | `none` | revert docs/client publish and redeploy_previous |
| S9 | Roll out the server compatibility flag for v2 serialization/validation in canary | SRE + Backend | S6, S7, S8 | `monitor:canary_error_rate_within_baseline` | disable the v2 schema/serialization flag and serve v1-compat |
| S10 | Monitor production validation rejection rate and audit-log coverage against the  | SRE + Security + DataPlatform | S9 | `monitor:validation-rejection-rate<=0.1% and monitor:audit_log_missing_events0` | shift traffic back to FastAPI 0.95.2 + Pydantic v1 deploymen |
| S11 | Continue dual-support operation for v1 and v2 clients while monitoring internal  | Backend + SRE + ConsumerSubsystem | S9 | `monitor:internal_client_v2_adoption>=80%` | restore v1-compatible request/response handling |
| S12 | After mobile apps are in users' hands and internal adoption reaches the threshol | Backend + SRE + ProductPM + ConsumerSubsystem | S6, S10, S11 | `window:dual-support until all critical internal services and mobile apps are on v2` | restore legacy fields and backfill missing values |

## SMT verification: 04-speed-tilted

- backend: `z3` (12 steps, 17 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- DataPlatform's blocking constraint requires `S6` before `S5` (gate `wait_for:published_openapi_v2_and_signed_off_schema_diff`)
- step `S6` depends_on `S5` (so `S5` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 04-speed-tilted

- **fragility (overall)**: 0.938
- **fragility curve**: budget=1 → 0.929, budget=2 → 1.0
- **avg severity**: 3.5 (1=low … 4=critical)
- **rollback-failure rate**: 0.312 (4/16 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=3, unrecoverable=1, redo_full=3
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | critical | yes | S3, S4, S5, S6, S7, S8 | manual_ops |
| S3 | gate_violation | critical | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | critical | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | critical | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | critical | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | high | yes | S12 | manual_ops |
| S11 | gate_violation | high | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | unrecoverable |
| S2 | rollback_failure | critical | NO | S3, S4, S5, S6, S7, S8 | redo_full |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | redo_full |
| S3, S6 | gate_violation | critical | NO | S4, S5, S6, S7, S8, S9 | redo_full |
| S4, S5 | gate_violation | critical | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |

## Plan: 05-speed-tilted (weights (0.5, 0.5, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Run secret rotation for the two tax-service validator endpoints and freeze relat | Security | — | `wait_for:secret_rotation_complete` | restore previous secret version and redeploy_previous |
| S2 | Apply bump-pydantic codemod, upgrade FastAPI to 0.110.x and Pydantic to 2.7+, th | Backend | S1 | `none` | redeploy_previous |
| S3 | Update the two async tax-service validator endpoints to a sync-safe design and p | Backend | S2 | `none` | disable_new_validation_path and redeploy_previous |
| S4 | Run compatibility and regression tests on the v2 codepath against recorded traff | Backend | S2, S3 | `wait_for:compatibility_tests_pass` | redeploy_previous |
| S5 | Publish the exact v2 OpenAPI artifact, regenerate @acme/payments-client@2.x and  | DataPlatform | S4 | `wait_for:published_openapi_v2_and_signed_off_schema_diff` | withdraw_v2_artifacts_and_republish_v1_artifacts |
| S6 | Send partner/integrator notice for all externally visible schema and behavior ch | ProductPM | S5 | `wait_for:partner-integrator-notice-sent` | revert docs/client publish and redeploy_previous |
| S7 | Release the mobile SDKs through app store submission and confirm the new builds  | Mobile | S5 | `wait_for:mobile SDK shipped and in user hands` | pull staged mobile release and publish previous SDK build |
| S8 | Deploy the backend with a feature-flagged compatibility path that serves v1-comp | SRE | S4, S6, S7 | `window:business-hours excluding Friday afternoon and incident windows` | disable the v2 schema/serialization flag and serve v1-compat |
| S9 | Monitor canary traffic and compare validation rejection rate, audit logging, and | SRE | S8 | `monitor:validation_rejection_rate<=0.1% above baseline` | shift traffic back to FastAPI 0.95.2 + Pydantic v1 deploymen |
| S10 | Promote the v2 schema/serialization flag for production while maintaining dual-s | SRE | S9 | `monitor:validation_rejection_rate<=0.1%` | disable the v2 schema/serialization flag and serve v1-compat |
| S11 | After 80% internal client adoption and mobile release completion, deprecate the  | Backend | S10 | `wait_for:30_day_quiet_period_with_no_legacy_field_usage` | restore legacy fields and backfill missing values |
| S12 | Update documentation site and publish the new API docs aligned to the exact v2 s | ProductPM | S10 | `window:after-committed_partner_notice_lead_time` | revert docs/client publish and redeploy_previous |

## SMT verification: 05-speed-tilted

- backend: `z3` (12 steps, 14 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S5` depends_on `S4` (so `S4` must be earlier)
- BackendOwner's blocking constraint requires `S5` before `S4` (gate `wait_for:compatibility_tests_pass`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 05-speed-tilted

- **fragility (overall)**: 0.933
- **fragility curve**: budget=1 → 1.0, budget=2 → 0.5
- **avg severity**: 3.33 (1=low … 4=critical)
- **rollback-failure rate**: 0.4 (6/15 probes)
- **recovery distribution**: manual_ops=2, recoverable_in_window=9, unrecoverable=4
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S3` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | gate_violation | critical | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | critical | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | medium | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | critical | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | critical | yes | S11, S12 | recoverable_in_window |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | unrecoverable |
| S2 | rollback_failure | critical | NO | S3, S4, S5, S6, S7, S8 | unrecoverable |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | unrecoverable |
| S2, S7 | gate_violation | critical | NO | S3, S4, S5, S6, S7, S8 | unrecoverable |
| S4, S2 | gate_violation | medium | NO | — | manual_ops |
