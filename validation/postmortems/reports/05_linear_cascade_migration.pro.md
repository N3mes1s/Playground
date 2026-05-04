# Verified Rollout (PRO) — 05_linear_cascade_migration

> Intent: /home/user/Playground/validation/postmortems/intents/05_linear_cascade_migration.md · N plans: 4 · Pareto-front size: 4 · Recommendation: 03-safety-tilted · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:39:31Z_

## Recommendation

**03-safety-tilted** — rank-0 (Pareto-optimal), utility -0.040 under user weights.

## Pareto frontier (NSGA-II)

_4 plans, 4 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 1.00 | 1.00 | 11 | 3.21 | 0.21 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | ∞ | 0.71 | 1.00 | 11 | 2.43 | 0.36 |
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | ∞ | 0.91 | 1.00 | 9 | 2.73 | 0.27 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | ∞ | 0.55 | 1.00 | 9 | 2.09 | 0.46 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
                     *                                     *
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*                                              *            
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.55, 1.00]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Merge and apply schema migration to create IssueAssignee with required indexes/c | DataPlatform | — | `wait_for:IssueAssignee table created and migrated successfully` | Drop IssueAssignee and revert to the pre-migration schema |
| S2 | Run bounded-batch backfill from Issue.assignee_id into IssueAssignee for all non | DataPlatform | S1 | `monitor:replication_lag<5m` | Stop the backfill job and delete inserted IssueAssignee rows |
| S3 | Deploy backward-compatible app code that reads from IssueAssignee and writes to  | BackendOwner | S1, S2 | `wait_for:backfill_complete_and_dual_write_verified` | redeploy_previous |
| S4 | Keep dual-write release live until parity is proven on production-shape data and | ConsumerSubsystem | S3 | `wait_for:read-path_parity_verified_on_production_shape_snapshot` | redeploy_previous |
| S5 | Pause for the required quiet period while monitoring for lagging reads, errors,  | SRE | S4 | `monitor:error_rate<0.1% for 24h` | redeploy_previous |
| S6 | Prepare and review Prisma-generated drop migration SQL, explicitly inspecting th | DataPlatform | S5 | `approval:storage` | Reject the migration and regenerate SQL without the cascadin |
| S7 | Obtain security review and explicit cascade-path confirmation for the destructiv | Security | S6 | `wait_for:explicit_cascade_review` | redeploy_previous |
| S8 | Confirm customer notice was sent at least 14 days before the destructive step an | ProductPM | S3 | `wait_for:customer_notice_sent_at_least_14_days_before_step_5` | pause rollout and keep legacy Issue.assignee_id path active |
| S9 | Schedule the final cutover/drop only inside an approved maintenance/business-saf | SRE | S8, S7 | `window:maintenance` | abort migration and reschedule to the next approved window |
| S10 | Run the final Prisma-generated migration to drop Issue.assignee_id after cutover | DataPlatform | S9, S7 | `approval:release-manager` | Re-add Issue.assignee_id and restore it from backup if neede |
| S11 | Verify post-drop stability and complete the migration only after the quiet perio | SRE | S10 | `wait_for:quiet_period_after_cutover` | restore Issue.assignee_id from backup or redeploy previous m |

## SMT verification: 00-cost-leaning

- backend: `z3` (11 steps, 13 dep edges, 6 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S4` depends_on `S3` (so `S3` must be earlier)
- SRE's blocking constraint requires `S4` before `S3` (gate `wait_for:backfill_complete_and_dual_write_stable`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 1.0
- **fragility curve**: budget=1 → 1.0, budget=2 → 1.0
- **avg severity**: 3.21 (1=low … 4=critical)
- **rollback-failure rate**: 0.214 (2/14 probes)
- **recovery distribution**: recoverable_in_window=5, manual_ops=7, redo_full=2
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S9, S10, S11 | manual_ops |
| S7 | gate_violation | high | yes | S9, S10, S11 | manual_ops |
| S8 | gate_violation | medium | yes | S9, S10, S11 | manual_ops |
| S9 | gate_violation | high | yes | S10, S11 | manual_ops |
| S10 | gate_violation | critical | yes | S11 | manual_ops |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | redo_full |
| S2 | rollback_failure | critical | NO | S3, S4, S5, S6, S7, S8 | redo_full |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | manual_ops |
| S4, S2 | gate_violation | critical | yes | S3, S4, S5, S6, S7, S8 | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Merge and apply Prisma migration that creates IssueAssignee(issue_id, user_id, . | DataPlatform | — | `approval:2_approvers_and:storage_and:security_and:api-owner` | Drop IssueAssignee and revert to the pre-migration schema. |
| S2 | Start the bounded-batch backfill from Issue.assignee_id into IssueAssignee using | DataPlatform | S1 | `monitor:replication_lag<5m` | Stop the backfill job and delete inserted IssueAssignee rows |
| S3 | Deploy application code that reads from IssueAssignee and dual-writes to both Is | BackendOwner | S1, S2 | `wait_for:IssueAssignee_table_created_and_backfill_job_running` | Redeploy previous application version. |
| S4 | Keep dual-write enabled until parity is proven on a production-shape snapshot an | BackendOwner | S3 | `monitor:backfill_and_dual_write_mismatch_rate=0 for 24h` | Redeploy previous application version with dual-read/dual-wr |
| S5 | Deploy code that reads and writes only IssueAssignee, while keeping the legacy w | ConsumerSubsystem | S4 | `wait_for:read-path_parity_verified_on_production_shape_snapshot` | Redeploy previous application version with dual-read/dual-wr |
| S6 | Announce customer/support readiness and name an escalation owner before any user | ProductPM | S3 | `window:customer_notice_before_release` | Pause rollout and keep legacy Issue.assignee_id path active. |
| S7 | Wait through the quiet period after dual-write/read cutover, with no launch wind | SRE | S5, S6 | `monitor:error_rate<0.1% for 24h` | Keep both schemas available and redeploy previous applicatio |
| S8 | Prepare and review the Prisma-generated drop migration SQL, explicitly checking  | DataPlatform | S7 | `wait_for:explicit_cascade_review` | Reject the migration and regenerate SQL without the cascadin |
| S9 | Obtain formal approvals for the destructive drop, including storage, security, r | SRE | S8 | `approval:storage_and:approval:security_and:approval:release-manager_and:approval:support_lead_ready` | Abort the cutover and keep the old column. |
| S10 | Execute the column drop for Issue.assignee_id in the maintenance window, only af | DataPlatform | S9 | `window:maintenance` | Re-add Issue.assignee_id and restore it from backup if neede |
| S11 | Run post-drop verification to confirm IssueAssignee is the source of truth and n | BackendOwner | S10 | `monitor:error_rate<0.1% for 24h` | Redeploy previous application version and restore the legacy |

## SMT verification: 01-safety-leaning

- backend: `z3` (11 steps, 12 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- SRE's blocking constraint requires `S4` before `S3` (gate `wait_for:backfill_complete_and_dual_write_stable`)
- step `S4` depends_on `S3` (so `S3` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.714
- **fragility curve**: budget=1 → 0.692, budget=2 → 1.0
- **avg severity**: 2.43 (1=low … 4=critical)
- **rollback-failure rate**: 0.357 (4/14 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=5
- **Achilles heel** (top 5 by per-step fragility):
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0
  - `S8` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S7, S8, S9, S10, S11 | recoverable_in_window |
| S5 | gate_violation | high | yes | S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S7, S8, S9, S10, S11 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9, S10, S11 | recoverable_in_window |
| S8 | gate_violation | medium | yes | S9, S10, S11 | recoverable_in_window |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S10 | gate_violation | high | yes | S11 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S3, S8 | gate_violation | critical | NO | S4, S5, S6, S7, S8, S9 | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Merge and apply the Prisma migration that creates IssueAssignee with required in | DataPlatform | — | `wait_for:IssueAssignee table created and migrated successfully` | Drop IssueAssignee and revert to the pre-migration schema |
| S2 | Run the bounded backfill job to copy each non-null Issue.assignee_id into IssueA | DataPlatform | S1 | `monitor:replication_lag<5m` | Stop the backfill job and delete inserted IssueAssignee rows |
| S3 | Deploy backward-compatible application code that reads from IssueAssignee and wr | BackendOwner | S1, S2 | `wait_for:backfill_complete_and_dual_write_verified` | redeploy_previous |
| S4 | Hold the dual-write release steady and verify read-path parity plus store matchi | ConsumerSubsystem | S3 | `monitor:backfill_and_dual_write_mismatch_rate=0` | redeploy_previous |
| S5 | Prepare the destructive drop PR by reviewing the generated Prisma SQL, explicitl | DataPlatform | S4 | `approval:storage` | Reject the migration and regenerate SQL without the cascadin |
| S6 | Publish customer/support communications for the upcoming cutover and confirm esc | ProductPM | S4 | `window:customer_notice_before_release` | pause rollout and keep legacy Issue.assignee_id path active |
| S7 | After the quiet period and once parity is stable, deploy code that reads and wri | BackendOwner | S4, S6 | `wait_for:quiet_period_after_cutover` | redeploy_previous |
| S8 | Execute the schema cutover in the maintenance window to drop Issue.assignee_id u | DataPlatform | S5, S7 | `window:maintenance` | Re-add Issue.assignee_id and restore it from backup if neede |
| S9 | Monitor post-cutover stability and confirm error rate remains below threshold fo | SRE | S8 | `monitor:error_rate<0.1% for 24h` | restore Issue.assignee_id from backup or redeploy previous m |

## SMT verification: 02-speed-leaning

- backend: `z3` (9 steps, 11 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S4` depends_on `S3` (so `S3` must be earlier)
- SRE's blocking constraint requires `S4` before `S3` (gate `wait_for:backfill_complete_and_dual_write_stable`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.909
- **fragility curve**: budget=1 → 0.9, budget=2 → 1.0
- **avg severity**: 2.73 (1=low … 4=critical)
- **rollback-failure rate**: 0.273 (3/11 probes)
- **recovery distribution**: manual_ops=4, recoverable_in_window=6, unrecoverable=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9 | recoverable_in_window |
| S5 | gate_violation | high | yes | S8, S9 | recoverable_in_window |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | yes | S8, S9 | recoverable_in_window |
| S8 | gate_violation | critical | yes | S9 | recoverable_in_window |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | unrecoverable |
| S2 | rollback_failure | high | NO | S3, S4, S5, S6, S7, S8 | manual_ops |
| S2, S4 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | manual_ops |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Create the IssueAssignee join table and required indexes/constraints; do not cha | DataPlatform | — | `wait_for:IssueAssignee table created and migrated successfully` | Drop IssueAssignee and revert to the pre-migration schema |
| S2 | Start bounded-batch backfill from Issue.assignee_id into IssueAssignee for all n | DataPlatform | S1 | `monitor:replication_lag<5m` | Stop the backfill job and delete inserted IssueAssignee rows |
| S3 | Deploy backward-compatible application code that continues old writes and adds d | BackendOwner | S1, S2 | `wait_for:IssueAssignee_table_created_and_backfill_job_running` | redeploy_previous |
| S4 | Verify dual-write/backfill parity and keep the dual-write path live until mismat | BackendOwner | S3 | `monitor:backfill_and_dual_write_mismatch_rate=0` | redeploy_previous |
| S5 | Deploy code that reads from IssueAssignee while still writing to both stores, ma | BackendOwner | S4 | `wait_for:read-path_parity_verified_on_production_shape_snapshot` | redeploy_previous |
| S6 | Hold the transition in a quiet period until post-cutover behavior is stable and  | SRE | S5 | `monitor:error_rate<0.1% for 24h` | redeploy_previous |
| S7 | Prepare the destructive drop PR by reviewing Prisma-generated SQL for unintended | DataPlatform | S6 | `approval:storage` | Reject the migration and regenerate SQL without the cascadin |
| S8 | Run the drop migration test on a production-shape copy to prove the generated DR | ConsumerSubsystem | S7 | `wait_for:drop_migration_test_passes_on_prod_shape_copy` | redeploy_previous |
| S9 | Execute the final schema cutover in the approved maintenance window: drop Issue. | DataPlatform | S8 | `window:maintenance` | Re-add Issue.assignee_id and restore it from backup if neede |

## SMT verification: 03-safety-tilted

- backend: `z3` (9 steps, 9 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (4 edges):
- step `S6` depends_on `S5` (so `S5` must be earlier)
- step `S5` depends_on `S4` (so `S4` must be earlier)
- DataPlatform's blocking constraint requires `S6` before `S3` (gate `wait_for:quiet_period_after_cutover`)
- step `S4` depends_on `S3` (so `S3` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.545
- **fragility curve**: budget=1 → 0.6, budget=2 → 0.0
- **avg severity**: 2.09 (1=low … 4=critical)
- **rollback-failure rate**: 0.455 (5/11 probes)
- **recovery distribution**: recoverable_in_window=6, manual_ops=5
- **Achilles heel** (top 5 by per-step fragility):
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S1` → 0.5

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S7, S8, S9 | recoverable_in_window |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S8, S7 | gate_violation | medium | NO | — | manual_ops |
