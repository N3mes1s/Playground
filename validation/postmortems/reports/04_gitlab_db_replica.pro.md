# Verified Rollout (PRO) — 04_gitlab_db_replica

> Intent: /home/user/Playground/validation/postmortems/intents/04_gitlab_db_replica.md · N plans: 4 · Pareto-front size: 4 · Recommendation: 00-cost-leaning · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:37:39Z_

## Recommendation

**00-cost-leaning** — rank-0 (Pareto-optimal), utility -0.055 under user weights.

## Pareto frontier (NSGA-II)

_4 plans, 4 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 0.50 | 1.00 | 11 | 2.43 | 0.57 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | ∞ | 0.60 | 1.00 | 12 | 1.80 | 0.40 |
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | ∞ | 0.85 | 1.00 | 10 | 2.38 | 0.31 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | ∞ | 0.99 | 1.00 | 12 | 2.50 | 0.21 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
            *                                              *
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*                                                           
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                         *                  
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.50, 0.99]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Confirm an escalation owner is assigned and notify on-call, DB owners, and suppo | ProductPM | — | `approval:on-call incident owner` | Revert escalation ownership to the prior duty owner and paus |
| S2 | Verify the rebuild is occurring in an approved low-risk window and not during in | SRE | S1 | `window:outside_incident_window_and_not_late_night` | Defer the rebuild and reschedule for a staffed maintenance w |
| S3 | SSH into the replica host and confirm the hostname is exactly db2.cluster.gitlab | SRE | S2 | `wait_for:hostname_confirmed_db2.cluster.gitlab.com` | Disconnect and reconnect only after explicit hostname verifi |
| S4 | Have the second engineer and observing engineer explicitly approve that the conn | SRE | S3 | `approval:second_engineer` | Abort the session and run no further commands. |
| S5 | Stop PostgreSQL on db2 and confirm it is fully stopped before any cleanup. | BackendOwner | S4 | `wait_for:postgresql stopped on db2` | Start PostgreSQL on db2 if stopped incorrectly and reassess  |
| S6 | Perform the pre-wipe checkpoint: observer confirms db2 identity again, then appr | ConsumerSubsystem | S5 | `approval:on_call_observer` | Skip the wipe and leave db2 stopped until re-approved. |
| S7 | Wipe only the PostgreSQL data directory on db2, preserving audit logs and any pr | BackendOwner | S6 | `none` | Restore the original data directory from the pre-wipe filesy |
| S8 | Run pg_basebackup from db1 to reseed db2 with a throughput limit that protects d | DataPlatform | S7 | `monitor:db1_replication_lag<30s` | Cancel pg_basebackup, clear the partial replica directory, a |
| S9 | Start PostgreSQL on db2 after basebackup completes and verify streaming replicat | BackendOwner | S8 | `monitor:replication_lag<0.1%` | Stop db2 and restore from the last known-good basebackup. |
| S10 | Confirm replication is fully caught up and stable before declaring db2 back in s | SRE | S9 | `monitor:replication_lag 0` | Keep db2 out of service and re-run the rebuild if lag does n |
| S11 | Release db2 to service and clean up any temporary preservation artifacts only af | DataPlatform | S10 | `wait_for:replication_caught_up_and_stable` | Retain old files or restore them from temporary preservation |

## SMT verification: 00-cost-leaning

- backend: `z3` (11 steps, 10 dep edges, 1 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10` → `S11`

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.5
- **fragility curve**: budget=1 → 0.538, budget=2 → 0.0
- **avg severity**: 2.43 (1=low … 4=critical)
- **rollback-failure rate**: 0.571 (7/14 probes)
- **recovery distribution**: recoverable_in_window=6, redo_full=1, manual_ops=7
- **Achilles heel** (top 5 by per-step fragility):
  - `S4` → 1.0
  - `S6` → 1.0
  - `S7` → 1.0
  - `S1` → 0.5
  - `S2` → 0.5

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11 | recoverable_in_window |
| S7 | gate_violation | critical | NO | S8, S9, S10, S11 | redo_full |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S10 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S5, S3 | gate_violation | medium | NO | — | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Notify on-call, DB owners, support, and assign a named escalation owner for the  | ProductPM | — | `approval:support lead` | Pause the rebuild and reschedule in the next approved low-ri |
| S2 | Open the SSH session to db2.cluster.gitlab.com with both engineers present; veri | SRE | S1 | `approval:second_engineer` | Abort the session and reconnect only after explicit db2 host |
| S3 | Record audit logs for the SSH session and preflight checks; confirm logging is a | Security | S2 | `none` | Stop work and restore audit logging before any further comma |
| S4 | Confirm db1.cluster.gitlab.com identity separately and verify it is serving prod | BackendOwner | S2 | `monitor:db1 write availability 100%` | Stop and re-verify host identity before any further action. |
| S5 | Stop PostgreSQL on db2 only after db2 identity is confirmed and the buddy check  | SRE | S3, S4 | `wait_for:postgresql stopped on db2` | Start PostgreSQL on db2 if it was stopped in error and reass |
| S6 | Perform a pre-wipe checkpoint: second engineer confirms db2 host identity, the o | DataPlatform | S5 | `approval:on_call_observer` | Skip the wipe and leave db2 stopped until re-approved. |
| S7 | Wipe only the PostgreSQL data directory on db2 with rm -rf after all confirmatio | BackendOwner | S6 | `approval:two_engineers` | Restore the original data directory from the pre-wipe filesy |
| S8 | Run pg_basebackup from db1 to db2 with throughput limited to protect db1 IOPS. | DataPlatform | S7 | `monitor:db1_replication_lag<30s` | Cancel pg_basebackup, clear the partially copied replica dir |
| S9 | Start PostgreSQL on db2 after basebackup completes. | SRE | S8 | `wait_for:pg_basebackup_complete` | Stop db2 PostgreSQL and restore from the last known-good bas |
| S10 | Verify replication health until lag is zero and stable; keep db2 out of service  | ConsumerSubsystem | S9 | `monitor:replication_lag0` | Stop db2 and re-run the rebuild if lag does not clear. |
| S11 | Hold the old replica files and temporary artifacts on db2 until replication catc | DataPlatform | S10 | `wait_for:replication_caught_up_and_stable` | Retain the old files or restore them from the temporary pres |
| S12 | Announce completion only after replication is healthy and db1 remained fully ava | ProductPM | S10, S11 | `monitor:db1 write availability 100%` | Publish a recovery update once replication is healthy again  |

## SMT verification: 01-safety-leaning

- backend: `z3` (12 steps, 13 dep edges, 0 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S4` → `S3` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10` → `S11` → `S12`

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.6
- **fragility curve**: budget=1 → 0.643, budget=2 → 0.0
- **avg severity**: 1.8 (1=low … 4=critical)
- **rollback-failure rate**: 0.4 (6/15 probes)
- **recovery distribution**: recoverable_in_window=9, manual_ops=6
- **Achilles heel** (top 5 by per-step fragility):
  - `S4` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S10` → 1.0
  - `S11` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | low | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | low | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | low | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S9, S3 | gate_violation | medium | NO | — | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Notify on-call, DB owners, support, and assign the named escalation owner; confi | SRE | — | `approval:on-call incident owner` | Pause the rebuild and reschedule in the next approved staffe |
| S2 | SSH to db2.cluster.gitlab.com and verify host identity before any service stop o | SecondEngineer | S1 | `approval:second_engineer` | Abort session and reconnect only after explicit hostname ver |
| S3 | Have the observing engineer perform a buddy check confirming the SSH target is d | SecondEngineer | S2 | `approval:second_engineer` | Abort the session and do not run any further commands. |
| S4 | Stop PostgreSQL on db2 and confirm the service is fully stopped before proceedin | DriverEngineer | S3 | `wait_for:postgresql stopped on db2` | Start PostgreSQL back on db2 if the rebuild is aborted befor |
| S5 | Wipe the db2 PostgreSQL data directory only after re-confirming the host is db2  | DriverEngineer | S4 | `approval:second_engineer` | Stop the wipe, preserve current state, and reconnect/re-veri |
| S6 | Run pg_basebackup from db1 to refill db2 with a rate limit that protects db1 IOP | DriverEngineer | S5 | `monitor:db1_replication_lag<30s` | Cancel pg_basebackup, clear the partially copied replica dir |
| S7 | Start PostgreSQL on db2 after basebackup completion. | DriverEngineer | S6 | `wait_for:pg_basebackup_complete` | Stop db2 and restore from the last known-good basebackup if  |
| S8 | Monitor replication health and lag until db2 is caught up and stable; keep db2 o | ObserverEngineer | S7 | `monitor:replication_lag0` | Keep db2 out of service and re-run the rebuild if lag does n |
| S9 | Validate that db1 continues serving production reads/writes throughout the rebui | ObserverEngineer | S1, S6, S8 | `monitor:db1 write availability 100%` | Redeploy previous |
| S10 | Declare success only after replication lag is zero/healthy and hand db2 back int | SRE | S8, S9 | `monitor:replication lag 0` | Keep db2 out of service and restore from the last known-good |

## SMT verification: 02-speed-leaning

- backend: `z3` (10 steps, 12 dep edges, 1 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10`

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.846
- **fragility curve**: budget=1 → 0.917, budget=2 → 0.0
- **avg severity**: 2.38 (1=low … 4=critical)
- **rollback-failure rate**: 0.308 (4/13 probes)
- **recovery distribution**: recoverable_in_window=8, manual_ops=3, unrecoverable=2
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S5` → 1.0
  - `S7` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | medium | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9, S10 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S9, S10 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10 | recoverable_in_window |
| S9 | gate_violation | critical | yes | S10 | manual_ops |
| S1 | rollback_failure | medium | NO | S2, S3, S4, S5, S6, S7 | unrecoverable |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | S4, S5, S6, S7, S8, S9 | unrecoverable |
| S6, S2 | gate_violation | medium | NO | — | manual_ops |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Send notifications to on-call, DB owners, and support; confirm named escalation  | ProductPM | — | `approval:support lead` | Pause the rebuild and resend notifications once support is r |
| S2 | Confirm the operation is in an approved off-peak maintenance window and not duri | SRE | S1 | `window:off-peak_maint` | Abort the rebuild and reschedule for the next staffed mainte |
| S3 | SSH to db2.cluster.gitlab.com from the driving engineer session and have the obs | SRE | S2 | `approval:second_engineer` | Disconnect immediately and reconnect only after explicit db2 |
| S4 | Record/confirm audit logging is active for SSH access and all destructive comman | Security | S3 | `none` | Halt the rebuild until audit logging is restored and verifia |
| S5 | Stop PostgreSQL on db2 only after the observer re-confirms the host identity and | BackendOwner | S4 | `wait_for:postgresql stopped on db2` | Start PostgreSQL on db2 again and abort the rebuild if the h |
| S6 | Before any wipe, perform a final two-engineer preflight: verify the shell hostna | Security | S5 | `approval:two_engineers` | Abort the session and do not run any further commands until  |
| S7 | Wipe only the PostgreSQL data directory on db2 with rm -rf, preserving audit log | DataPlatform | S6 | `approval:second_engineer` | Stop the wipe immediately and restore the original data dire |
| S8 | Run pg_basebackup from db1 to refill db2, using a throughput limit that protects | DataPlatform | S7 | `monitor:db1_replication_lag<30s` | Cancel pg_basebackup, clear the partially copied replica dir |
| S9 | Start PostgreSQL on db2 after basebackup completes and keep the old replica arti | BackendOwner | S8 | `wait_for:pg_basebackup_complete` | Stop db2 and restore the preserved prior state or last known |
| S10 | Validate replication health and lag continuously until it is fully caught up and | SRE | S9 | `monitor:replication_lag<0.1%` | Keep db2 out of service and re-run the rebuild if lag does n |
| S11 | After stable catch-up, remove any preserved old replica files and temporary arti | DataPlatform | S10 | `wait_for:replication_caught_up_and_stable` | Retain the old files or restore them from the temporary pres |
| S12 | Hand back the rebuilt replica for normal use and confirm db1 write availability  | BackendOwner | S10 | `monitor:db1 write availability 100%` | Redeploy previous |

## SMT verification: 03-safety-tilted

- backend: `z3` (12 steps, 11 dep edges, 0 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10` → `S11` → `S12`

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.99
- **fragility curve**: budget=1 → 1.0, budget=2 → 0.857
- **avg severity**: 2.5 (1=low … 4=critical)
- **rollback-failure rate**: 0.214 (2/14 probes)
- **recovery distribution**: recoverable_in_window=13, unrecoverable=1
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S2` → 1.0
  - `S3` → 1.0
  - `S4` → 1.0
  - `S6` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | low | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | medium | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | high | yes | S6, S7, S8, S9, S10, S11 | recoverable_in_window |
| S6 | gate_violation | high | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | critical | yes | S8, S9, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S10, S11, S12 | recoverable_in_window |
| S9 | gate_violation | high | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | rollback_failure | medium | NO | S3, S4, S5, S6, S7, S8 | unrecoverable |
| S3 | rollback_failure | medium | NO | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S8, S5 | gate_violation | critical | yes | S6, S7, S9, S10, S11, S12 | recoverable_in_window |
