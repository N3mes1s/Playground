# Verified Rollout (PRO) — 01_atlassian_app_deletion

> Intent: /home/user/Playground/validation/postmortems/intents/01_atlassian_app_deletion.md · N plans: 4 · Pareto-front size: 2 · Recommendation: 03-safety-tilted · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:28:25Z_

## Recommendation

**03-safety-tilted** — rank-0 (Pareto-optimal), utility -0.080 under user weights.

## Pareto frontier (NSGA-II)

_4 plans, 2 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 0.73 | 1.00 | 12 | 2.47 | 0.27 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | ∞ | 0.53 | 1.00 | 12 | 2.67 | 0.47 |
| 01-safety-leaning | 0.00/1.00/0.00 | 1 | ∞ | 0.80 | 1.00 | 12 | 2.47 | 0.33 |
| 02-speed-leaning | 1.00/0.00/0.00 | 1 | ∞ | 0.73 | 1.00 | 12 | 2.53 | 0.27 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*                                           .              .
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.53, 0.80]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Team A exports a versioned CSV of Insight app-install IDs only, with schema docu | Team A | — | `approval:security` | Discard the CSV and regenerate a fresh, signed identifier li |
| S2 | Security and Storage validate the CSV against app-install records, confirm targe | Security | S1 | `approval:security` | stop bulk-delete and regenerate CSV from app-install invento |
| S3 | ProductPM sends customer notifications, assigns a named escalation owner, and br | ProductPM | S1 | `approval:support_manager` | pause rollout and issue support update |
| S4 | Schedule execution only in an approved window outside launch windows, major even | SRE | S2, S3 | `window:business-hours-only;no-friday-afternoon;no-incident-window;outside_launch_windows_and_major_events` | Defer execution to the next approved window and cancel the c |
| S5 | Deploy the validated cleanup.py parser and CSV schema checks before any destruct | BackendOwner | S2 | `wait_for:validation_build_deployed` | redeploy_previous |
| S6 | Run a non-destructive preflight dry-run on the frozen CSV to prove every ID maps | SRE | S4, S5 | `wait_for:preflight_audit_pass` | Reject the CSV and rerun validation after fixing identifiers |
| S7 | Obtain final compliance sign-off and release-manager approval for the deletion p | Security | S6 | `approval:compliance` | Abort rollout and restore the previous deprecation hold |
| S8 | Run a single-site canary delete on a known-safe test ID using the validated work | Team B | S7 | `monitor:error_rate<0.1%` | Stop the run and restore the canary batch from backup before |
| S9 | Verify the canary remains stable before proceeding to the bulk run. | SRE | S8 | `wait_for:24h_stable_canary` | Abort remaining batches and redeploy_previous of the cleanup |
| S10 | Execute the bulk deletion in small batches with IOPS-safe pacing, preserving aud | Team B | S9 | `monitor:iops<70%` | pause batch processing and resume from last confirmed batch |
| S11 | Continuously monitor replication lag during the bulk run and halt if it exceeds  | DataPlatform | S10 | `monitor:replication_lag<60s` | pause deletions until lag returns under budget, then continu |
| S12 | After all deletes complete and the quiet period is reached, remove legacy Insigh | DataPlatform | S10, S11 | `window:after_business_hours` | recreate dropped tables from backup/DDL if quiet-period chec |

## SMT verification: 00-cost-leaning

- backend: `z3` (12 steps, 14 dep edges, 2 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (4 edges):
- step `S6` depends_on `S5` (so `S5` must be earlier)
- step `S7` depends_on `S6` (so `S6` must be earlier)
- step `S8` depends_on `S7` (so `S7` must be earlier)
- BackendOwner's blocking constraint requires `S8` before `S5` (gate `wait_for:dry_run_success`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.733
- **fragility curve**: budget=1 → 0.786, budget=2 → 0.0
- **avg severity**: 2.47 (1=low … 4=critical)
- **rollback-failure rate**: 0.267 (4/15 probes)
- **recovery distribution**: recoverable_in_window=11, manual_ops=4
- **Achilles heel** (top 5 by per-step fragility):
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0
  - `S8` → 1.0
  - `S9` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | high | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | high | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S10, S4 | gate_violation | medium | NO | — | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Team A exports a versioned CSV from the customer catalogue using the app-install | Team A | — | `approval:security` | Discard the CSV and regenerate a fresh, signed identifier li |
| S2 | Security and Storage validate the frozen CSV against Insight app-install records | Security | S1 | `wait_for:preflight_audit_pass` | Stop bulk-delete and regenerate CSV from app-install invento |
| S3 | Team B deploys parser and validation changes to cleanup.py so the ingestion path | Team B | S2 | `wait_for:validation_build_deployed` | Redeploy previous cleanup.py build |
| S4 | Product and Support send customer notifications, assign a single escalation owne | ProductPM | S1 | `approval:support_manager` | Pause rollout and issue support update |
| S5 | Schedule the run only in an approved window outside launch windows, major events | SRE | S3, S4 | `window:business-hours-only;no-friday-afternoon;no-incident-window;outside_launch_windows_and_major_events` | Defer execution to the next approved window and cancel the c |
| S6 | Run a non-destructive dry-run on a known-safe test ID to prove the workflow targ | Team B | S3, S5 | `monitor:error_rate<0.1%` | Redeploy previous workflow and stop the run |
| S7 | Obtain final compliance approval to proceed with customer-deletable data removal | Security | S2, S6 | `approval:compliance` | Abort rollout and restore the previous deprecation hold |
| S8 | Run a canary delete on a tiny sampled batch of validated app IDs from the CSV, w | Team B | S6, S7 | `monitor:error_rate<0.1%` | Stop the run and restore the canary batch from backup before |
| S9 | Hold the rollout for 24 hours after the canary and require no customer-impacting | SRE | S8 | `wait_for:24h_stable_canary` | Abort remaining batches and redeploy_previous of the cleanup |
| S10 | Execute bulk deletion in small batches with IOPS-safe pacing, deleting only app  | Team B | S9 | `monitor:iops<70%` | Pause batch processing and resume from the last confirmed ba |
| S11 | Continuously halt the run if replication lag exceeds the migration budget, then  | DataPlatform | S10 | `monitor:replication_lag<60s` | Pause deletions until lag returns under budget, then continu |
| S12 | After all deletes complete, perform post-delete schema cleanup for legacy Insigh | DataPlatform | S11 | `window:after_business_hours` | Recreate dropped tables from backup/DDL if quiet-period chec |

## SMT verification: 01-safety-leaning

- backend: `z3` (12 steps, 15 dep edges, 2 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S3` depends_on `S2` (so `S2` must be earlier)
- BackendOwner's blocking constraint requires `S3` before `S2` (gate `wait_for:sample_csv_validation_pass`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.8
- **fragility curve**: budget=1 → 0.786, budget=2 → 1.0
- **avg severity**: 2.47 (1=low … 4=critical)
- **rollback-failure rate**: 0.333 (4/15 probes)
- **recovery distribution**: recoverable_in_window=10, manual_ops=4, redo_full=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | medium | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | high | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | critical | NO | S3, S5, S6, S7, S8, S9 | redo_full |
| S3 | rollback_failure | high | NO | S5, S6, S7, S8, S9, S10 | manual_ops |
| S6, S9 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Collect Team A's CSV and perform schema/version checks plus app-install record v | Team A | — | `wait_for:sample_csv_validation_pass` | stop bulk-delete and regenerate CSV from app-install invento |
| S2 | Freeze the validated CSV handoff, secure audit logging for the artifact, and obt | Security | S1 | `approval:security` | Discard the CSV and regenerate a fresh, signed identifier li |
| S3 | Deploy cleanup.py parser/validation changes that enforce versioned CSV parsing a | Team B | S1 | `wait_for:validation_build_deployed` | redeploy_previous |
| S4 | Prepare customer notification, support briefing, and schedule the run inside an  | ProductPM | S2 | `window:customer_notice_sent_and_elapsed` | Pause rollout and re-enable the app until notice window comp |
| S5 | Run a single-site dry run on a known-safe test ID and a preflight audit that pro | SRE | S2, S3 | `wait_for:preflight_audit_pass` | Stop the job and restore from the preflight-only state |
| S6 | Obtain explicit go-ahead from ops/oncall and storage owner after the CSV and dry | Ops | S5 | `approval:ops-oncall` | Reject the CSV and rerun validation after fixing identifiers |
| S7 | Start a tiny canary delete batch using the validated CSV and confirm audit cover | Team B | S4, S5, S6 | `monitor:error_rate<0.1%` | Stop the run and restore the canary batch from backup before |
| S8 | Pause after the canary and wait for stability confirmation before expanding beyo | SRE | S7 | `wait_for:24h_stable_canary` | Abort remaining batches and redeploy_previous of the cleanup |
| S9 | Execute the full bulk deletion in small paced batches, keeping deletion only on  | Team B | S8 | `monitor:iops<70%` | pause batch processing and resume from last confirmed batch |
| S10 | Continuously monitor replication lag during bulk deletion and halt if it exceeds | DataPlatform | S9 | `monitor:replication_lag<60s` | pause deletions until lag returns under budget, then continu |
| S11 | After completion and only in the allowed quiet period, remove legacy Insight tab | DataPlatform | S10 | `window:after_business_hours` | recreate dropped tables from backup/DDL if quiet-period chec |
| S12 | Close out with final audit review and compliance sign-off that all targets were  | Security | S9, S10, S11 | `approval:compliance` | Abort rollout and restore the previous deprecation hold |

## SMT verification: 02-speed-leaning

- backend: `z3` (12 steps, 16 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S3` depends_on `S1` (so `S1` must be earlier)
- BackendOwner's blocking constraint requires `S3` before `S1` (gate `wait_for:sample_csv_validation_pass`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.733
- **fragility curve**: budget=1 → 0.714, budget=2 → 1.0
- **avg severity**: 2.53 (1=low … 4=critical)
- **rollback-failure rate**: 0.267 (4/15 probes)
- **recovery distribution**: recoverable_in_window=11, manual_ops=4
- **Achilles heel** (top 5 by per-step fragility):
  - `S4` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0
  - `S8` → 1.0
  - `S9` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | critical | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | medium | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | high | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | medium | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S4, S7 | gate_violation | critical | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Team A exports a versioned CSV of identifiers from the customer-site catalogue a | Team A | — | `approval:security` | Discard the CSV and regenerate a fresh, signed identifier li |
| S2 | Validate the CSV schema and confirm every row maps to app-install records for In | Team B | S1 | `wait_for:sample_csv_validation_pass` | stop bulk-delete and regenerate CSV from app-install invento |
| S3 | Deploy updated cleanup.py parsing/validation that accepts only the validated CSV | Team B | S2 | `wait_for:validation_build_deployed` | redeploy_previous |
| S4 | Run the required pre-flight dry-run on the validated CSV to prove target granula | Team B | S3 | `wait_for:preflight_audit_pass` | Stop the job and restore from the preflight-only state |
| S5 | Execute a single-site canary delete using a known-safe test ID that resolves to  | Team B | S4 | `monitor:error_rate<0.1%` | Stop the run and restore the canary batch from backup before |
| S6 | Obtain the required customer notification complete signal and support readiness  | ProductPM | S1 | `wait_for:customer_notification_complete` | pause rollout and re-enable the app until notice window comp |
| S7 | Secure final cross-functional approvals for support, compliance, storage ownersh | ProgramOwner | S2, S6 | `approval:compliance` | Abort rollout and restore the previous deprecation hold |
| S8 | Run the bulk delete in small paced batches against the validated app IDs, with t | Team B | S5, S7 | `monitor:iops<70%` | pause batch processing and resume from last confirmed batch |
| S9 | Continue batch deletion only while replication lag stays within budget and the c | Team B | S8 | `monitor:replication_lag<60s` | pause deletions until lag returns under budget, then continu |
| S10 | After the batch run completes, verify audit coverage is complete for CSV source, | Security | S9 | `monitor:audit_coverage=100%` | Halt execution and re-run only after logging is restored |
| S11 | Perform post-delete schema cleanup for legacy Insight tables only during the app | DataPlatform | S10 | `window:after_business_hours` | recreate dropped tables from backup/DDL if quiet-period chec |
| S12 | Close out the rollout by confirming all target sites no longer have Insight inst | ProgramOwner | S11 | `none` | redeploy_previous |

## SMT verification: 03-safety-tilted

- backend: `z3` (12 steps, 13 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- BackendOwner's blocking constraint requires `S3` before `S2` (gate `wait_for:sample_csv_validation_pass`)
- step `S3` depends_on `S2` (so `S2` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.533
- **fragility curve**: budget=1 → 0.571, budget=2 → 0.0
- **avg severity**: 2.67 (1=low … 4=critical)
- **rollback-failure rate**: 0.467 (7/15 probes)
- **recovery distribution**: recoverable_in_window=6, manual_ops=9
- **Achilles heel** (top 5 by per-step fragility):
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0
  - `S10` → 1.0
  - `S1` → 0.5

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | critical | yes | S3, S4, S5, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S8, S9, S10, S11 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S8, S9, S10, S11, S12 | recoverable_in_window |
| S5 | gate_violation | critical | yes | S8, S9, S10, S11, S12 | manual_ops |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S10 | gate_violation | high | yes | S11, S12 | manual_ops |
| S11 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S4, S11 | gate_violation | medium | NO | — | manual_ops |
