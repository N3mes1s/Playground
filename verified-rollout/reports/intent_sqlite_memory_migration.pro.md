# Verified Rollout (PRO) — intent_sqlite_memory_migration

> Intent: fixtures/intent_sqlite_memory_migration.md · N plans: 6 · Pareto-front size: 6 · Recommendation: 04-speed-tilted · Utility weights: {"fragility": 0.4, "coverage": 0.3, "steps": 0.1, "severity": 0.15, "rollback_failure": 0.05} · Model: gpt-5.4-mini

_Generated 2026-04-29T20:06:44Z_

## Recommendation

**04-speed-tilted** — rank-0 (Pareto-optimal), utility 0.122 under user weights.

## Pareto frontier (NSGA-II)

_6 plans, 6 on the Pareto front._

| Plan | Weights (s/sf/c) | Rank | Crowding | Fragility | Cov | Steps | Severity | RB-fail |
|---|---|---|---|---|---|---|---|---|
| 00-cost-leaning | 0.00/0.00/1.00 | 0 | ∞ | 0.65 | 1.00 | 12 | 2.60 | 0.53 |
| 01-safety-leaning | 0.00/1.00/0.00 | 0 | ∞ | 0.69 | 1.00 | 12 | 2.50 | 0.25 |
| 04-speed-tilted | 0.50/0.00/0.50 | 0 | ∞ | 0.07 | 1.00 | 10 | 2.07 | 0.93 |
| 05-speed-tilted | 0.50/0.50/0.00 | 0 | ∞ | 0.50 | 1.00 | 10 | 2.50 | 0.57 |
| 02-speed-leaning | 1.00/0.00/0.00 | 0 | 1.56 | 0.17 | 1.00 | 10 | 2.17 | 0.83 |
| 03-safety-tilted | 0.00/0.50/0.50 | 0 | 1.11 | 0.36 | 1.00 | 10 | 2.14 | 0.64 |

## Pareto chart

```
y=steps (lower is better) ↑    Pareto front: '*'   dominated: '.'
                                                       *   *
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
                                                            
*        *                 *            *                   
────────────────────────────────────────────────────────────
        x=fragility (lower is better) →   range [0.07, 0.69]
```

## Plan: 00-cost-leaning (weights (0.0, 0.0, 1.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with init, append/write, read/q | BackendOwner | — | `none` | Disable sqlite backend and route persistence back to jsonl. |
| S2 | Add Agent backend selection via backend='sqlite' kwarg and MIROFISH_MEMORY_BACKE | BackendOwner | S1 | `none` | Reset backend selection to jsonl without changing LocalMemor |
| S3 | Add migrate_jsonl_to_sqlite() to read all .mirofish_memory/*.jsonl files and imp | BackendOwner | S1 | `none` | Delete .mirofish_memory/memory.db and rerun migration from J |
| S4 | Add schema/table/index creation and cross-run query support for tags/time ranges | BackendOwner | S1, S3 | `window:off_hours` | Drop newly created SQLite database and keep JSONL backend ac |
| S5 | Run concurrency, restart persistence, and migration helper tests for sqlite writ | ConsumerSubsystem | S2, S3, S4 | `approval:release_manager` | Redeploy previous revision. |
| S6 | Perform security/permissions review for memory.db creation and local file access | Security | S4 | `approval:security` | Disable sqlite backend and redeploy_previous. |
| S7 | Run migrate_jsonl_to_sqlite() for existing .mirofish_memory JSONL files and vali | DataPlatform | S4, S5, S6 | `wait_for:migration_reconciliation_verified` | Clear memory.db and re-import from JSONL. |
| S8 | Deploy sqlite backend code with MIROFISH_MEMORY_BACKEND still defaulting to json | BackendOwner | S5, S6 | `none` | Revert backend selection to jsonl and keep LocalMemory signa |
| S9 | Publish migration guidance and customer announcement for JSONL->SQLite opt-in, i | ProductPM | S8 | `approval:docs` | Remove opt-in docs and keep JSONL path documented as primary |
| S10 | Enable opt-in sqlite usage for selected runs after migration validation, keeping | ProductPM | S7, S9 | `window:one_release` | Set MIROFISH_MEMORY_BACKEND=jsonl and stop using memory.db. |
| S11 | Retain legacy JSONL files until a quiet period verifies no JSONL reads for 7 day | DataPlatform | S10 | `wait_for:7d_no_jsonl_reads_after_cutover` | Restore JSONL files from backup and switch backend back to j |
| S12 | After one release notice period, low error rate, and non-incident business windo | ProductPM | S10 | `window:after_one_release_notice_period` | Keep default on jsonl for the current release. |

## SMT verification: 00-cost-leaning

- backend: `z3` (12 steps, 18 dep edges, 3 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S8` → `S9` → `S7` → `S10` → `S11` → `S12`

## Chaos probe: 00-cost-leaning

- **fragility (overall)**: 0.648
- **fragility curve**: budget=1 → 0.747, budget=2 → 0.0
- **avg severity**: 2.6 (1=low … 4=critical)
- **rollback-failure rate**: 0.533 (7/15 probes)
- **recovery distribution**: manual_ops=8, recoverable_in_window=4, redo_full=3
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S3` → 1.0
  - `S5` → 1.0
  - `S6` → 1.0
  - `S9` → 1.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | gate_violation | high | yes | S5, S8, S9, S10, S11, S12 | manual_ops |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | manual_ops |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S6 | gate_violation | medium | yes | S7, S8, S9, S10, S11, S12 | recoverable_in_window |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | yes | S10, S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | redo_full |
| S2 | rollback_failure | critical | NO | S5, S8, S9, S10, S11, S12 | redo_full |
| S3 | rollback_failure | critical | NO | S4, S5, S6, S7, S8, S9 | redo_full |
| S10, S7 | gate_violation | medium | NO | — | manual_ops |
| S7, S4 | gate_violation | medium | NO | — | manual_ops |

## Plan: 01-safety-leaning (weights (0.0, 1.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with stdlib sqlite3, keep Local | BackendOwner | — | `none` | disable sqlite backend and route persistence back to jsonl |
| S2 | Add Agent backend selection in mirofish_lab/agent.py via backend="sqlite" kwarg  | ConsumerSubsystem | S1 | `none` | set MIROFISH_MEMORY_BACKEND=jsonl and remove sqlite opt-in |
| S3 | Implement migrate_jsonl_to_sqlite() to import all existing .mirofish_memory/*.js | BackendOwner | S1 | `none` | delete .mirofish_memory/memory.db and rerun migration with s |
| S4 | Add tests for concurrent writes, restart persistence, legacy JSONL reads through | ConsumerSubsystem | S1, S2, S3 | `approval:release_manager` | redeploy_previous |
| S5 | Run schema creation and initial migration in an off-hours window on a staging or | DataPlatform | S3, S4 | `window:off_hours` | drop newly created SQLite database and keep JSONL backend ac |
| S6 | Complete security review for memory.db permissions and local access before expos | Security | S5 | `approval:security` | disable sqlite backend and redeploy_previous |
| S7 | Publish migration guidance and support playbook for opt-in SQLite use, including | ProductPM | S2, S3 | `approval:docs` | remove opt-in docs and keep JSONL path documented as primary |
| S8 | Enable sqlite opt-in for a limited validation cohort using MIROFISH_MEMORY_BACKE | SRE | S5, S6, S7 | `wait_for:migration_validation_complete` | set MIROFISH_MEMORY_BACKEND=jsonl and stop using memory.db |
| S9 | Keep legacy JSONL files present and readable while monitoring for 7 days after c | DataPlatform | S8 | `monitor:sqlite_busy_errors<1%` | restore JSONL files from backup and switch backend back to j |
| S10 | Send customer announcement and release notice for the upcoming default-backend c | ProductPM | S7 | `wait_for:customer_announcement_sent` | Restore JSONL as the default backend and pause rollout |
| S11 | After one release notice period and during an approved non-incident business-hou | BackendOwner | S8, S9, S10 | `monitor:sqlite_write_error_rate<0.1% for 24h` | revert default backend to jsonl |
| S12 | Once 7 days pass with no JSONL reads after cutover, remove legacy JSONL files or | DataPlatform | S11 | `wait_for:7d_no_jsonl_reads_after_cutover` | restore JSONL files from backup and switch backend back to j |

## SMT verification: 01-safety-leaning

- backend: `z3` (12 steps, 19 dep edges, 5 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- Security's blocking constraint requires `S9` before `S8` (gate `wait_for:migration_reconciliation_verified`)
- step `S9` depends_on `S8` (so `S8` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 01-safety-leaning

- **fragility (overall)**: 0.689
- **fragility curve**: budget=1 → 0.73, budget=2 → 0.4
- **avg severity**: 2.5 (1=low … 4=critical)
- **rollback-failure rate**: 0.25 (4/16 probes)
- **recovery distribution**: recoverable_in_window=12, manual_ops=4
- **Achilles heel** (top 5 by per-step fragility):
  - `S5` → 1.0
  - `S8` → 1.0
  - `S10` → 1.0
  - `S11` → 1.0
  - `S9` → 0.9

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S4, S7, S8, S9, S10, S11 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S8, S9, S11, S12 | recoverable_in_window |
| S6 | gate_violation | high | yes | S8, S11, S12 | recoverable_in_window |
| S7 | gate_violation | high | yes | S8, S10, S11, S12 | recoverable_in_window |
| S8 | gate_violation | high | yes | S9, S11, S12 | recoverable_in_window |
| S9 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S10 | gate_violation | medium | yes | S11, S12 | recoverable_in_window |
| S11 | gate_violation | medium | yes | S12 | recoverable_in_window |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S7, S9 | gate_violation | high | yes | S8, S10, S11, S12 | recoverable_in_window |
| S2, S4 | gate_violation | medium | NO | — | manual_ops |

## Plan: 02-speed-leaning (weights (1.0, 0.0, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with schema creation, durable w | BackendOwner | — | `none` | revert the backend selection to jsonl and keep LocalMemory s |
| S2 | Add Agent backend selection in mirofish_lab/agent.py using backend="jsonl" defau | BackendOwner | S1 | `none` | switch backend selection back to jsonl without redeploy |
| S3 | Add migration helper migrate_jsonl_to_sqlite() that imports all .mirofish_memory | BackendOwner | S1 | `monitor:iops<80%` | delete .mirofish_memory/memory.db and rerun migration with s |
| S4 | Run concurrency, restart-persistence, and migration tests for the sqlite path, i | ConsumerSubsystem | S2, S3 | `wait_for:migration_helper_tests_pass` | redeploy_previous |
| S5 | Perform off-hours deployment of schema-creating SQLite init and migration-capabl | DataPlatform | S4 | `window:off_hours` | drop newly created SQLite database and keep JSONL backend ac |
| S6 | Opt in selected runs to sqlite via MIROFISH_MEMORY_BACKEND=sqlite and validate s | SRE | S5 | `wait_for:migration_validation_complete` | set MIROFISH_MEMORY_BACKEND=jsonl and stop using memory.db |
| S7 | Monitor sqlite write errors, busy-locks, and import/query correctness during opt | DataPlatform | S6 | `monitor:sqlite_busy_errors<1%` | re-enable JSONL writes and pause SQLite writes until content |
| S8 | Publish migration guidance, brief support, assign escalation ownership, and send | ProductPM | S5 | `approval:support_lead` | remove opt-in docs and keep JSONL path documented as primary |
| S9 | After one full release notice period and low error metrics, flip the default bac | BackendOwner | S7, S8 | `window:after_one_release_notice_period` | reset default backend to jsonl |
| S10 | Retain legacy JSONL files until parity is proven over a quiet period, then depre | DataPlatform | S6 | `wait_for:7d_no_jsonl_reads_after_cutover` | restore JSONL files from backup and switch backend back to j |

## SMT verification: 02-speed-leaning

- backend: `z3` (10 steps, 11 dep edges, 3 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- ProductPM's blocking constraint requires `S5` before `S4` (gate `wait_for:customer_announcement_sent`)
- step `S5` depends_on `S4` (so `S4` must be earlier)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 02-speed-leaning

- **fragility (overall)**: 0.167
- **fragility curve**: budget=1 → 0.2, budget=2 → 0.0
- **avg severity**: 2.17 (1=low … 4=critical)
- **rollback-failure rate**: 0.833 (9/12 probes)
- **recovery distribution**: recoverable_in_window=2, manual_ops=10
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 0.5
  - `S2` → 0.333
  - `S3` → 0.0
  - `S4` → 0.0
  - `S5` → 0.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | medium | NO | — | manual_ops |
| S4 | gate_violation | medium | NO | — | manual_ops |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S8, S2 | gate_violation | medium | NO | — | manual_ops |
| S5, S6 | gate_violation | medium | NO | — | manual_ops |

## Plan: 03-safety-tilted (weights (0.0, 0.5, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with sqlite3-only storage, sche | BackendOwner | — | `none` | disable sqlite backend and route persistence back to jsonl |
| S2 | Keep LocalMemory signature unchanged and make it a compatibility shim that reads | ConsumerSubsystem | S1 | `none` | redeploy_previous |
| S3 | Add Agent backend selection in mirofish_lab/agent.py with backend="sqlite" opt-i | ConsumerSubsystem | S2 | `approval:release_manager` | set MIROFISH_MEMORY_BACKEND=jsonl and remove sqlite opt-in |
| S4 | Implement migrate_jsonl_to_sqlite() to import all .mirofish_memory JSONL files i | DataPlatform | S1, S2 | `window:off_hours` | delete .mirofish_memory/memory.db and rerun migration with s |
| S5 | Add migration and concurrency/restart tests covering JSONL import, sqlite readba | ConsumerSubsystem | S3, S4 | `approval:release_manager` | redeploy_previous |
| S6 | Ship the sqlite-capable code path, migration helper, and compatibility shim whil | BackendOwner | S5 | `wait_for:sqlite backend deployed and migration helper available` | redeploy_previous |
| S7 | Run migrate_jsonl_to_sqlite() for existing repos during the approved off-hours w | DataPlatform | S6 | `wait_for:successful migration of existing .mirofish_memory JSONL files` | clear memory.db and re-import from JSONL |
| S8 | Enable MIROFISH_MEMORY_BACKEND=sqlite as an opt-in for users who want sqlite-bac | ProductPM | S7 | `wait_for:migration_validation_complete` | set MIROFISH_MEMORY_BACKEND=jsonl and stop using memory.db |
| S9 | After one release, flip the default backend to sqlite for new runs while keeping | BackendOwner | S8 | `window:one_release` | reset default backend to jsonl |
| S10 | Keep legacy JSONL files present until parity is verified after a quiet period, t | DataPlatform | S9 | `wait_for:7d_no_jsonl_reads_after_cutover` | restore JSONL files from backup and switch backend back to j |

## SMT verification: 03-safety-tilted

- backend: `z3` (10 steps, 11 dep edges, 5 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S4` → `S3` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10`

## Chaos probe: 03-safety-tilted

- **fragility (overall)**: 0.357
- **fragility curve**: budget=1 → 0.417, budget=2 → 0.0
- **avg severity**: 2.14 (1=low … 4=critical)
- **rollback-failure rate**: 0.643 (9/14 probes)
- **recovery distribution**: recoverable_in_window=5, manual_ops=9
- **Achilles heel** (top 5 by per-step fragility):
  - `S4` → 1.0
  - `S1` → 0.5
  - `S3` → 0.5
  - `S5` → 0.5
  - `S2` → 0.333

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S3, S4, S5, S6, S7, S8 | recoverable_in_window |
| S3 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S4 | gate_violation | medium | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | yes | S6, S7, S8, S9, S10 | recoverable_in_window |
| S6 | gate_violation | medium | NO | — | manual_ops |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | NO | — | manual_ops |
| S1 | rollback_failure | medium | NO | — | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S5, S9 | gate_violation | medium | NO | — | manual_ops |
| S2, S7 | gate_violation | medium | NO | — | manual_ops |

## Plan: 04-speed-tilted (weights (0.5, 0.0, 0.5))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py, keep LocalMemory signature sta | BackendOwner | — | `none` | revert backend selection to jsonl and keep LocalMemory signa |
| S2 | Add migration helper migrate_jsonl_to_sqlite() and compatibility reads from lega | BackendOwner | S1 | `none` | disable sqlite backend and route persistence back to jsonl |
| S3 | Add concurrency, restart persistence, and migration validation tests for sqlite  | ConsumerSubsystem | S1, S2 | `approval:release_manager` | redeploy_previous |
| S4 | Create memory.db schema and indexes, verify file permissions, and run the one-ti | DataPlatform | S2, S3 | `window:off_hours` | drop newly created SQLite database and keep JSONL backend ac |
| S5 | Validate migrated data reconciliation and confirm existing JSONL history is pres | Security | S4 | `wait_for:migration_reconciliation_verified` | restore JSONL-only writes and keep existing JSONL files as s |
| S6 | Publish migration guidance, brief support, and assign escalation ownership for s | ProductPM | S5 | `approval:docs` | remove opt-in docs and keep JSONL path documented as primary |
| S7 | Enable sqlite opt-in for users by setting MIROFISH_MEMORY_BACKEND=sqlite after m | BackendOwner | S5, S6 | `wait_for:customer_announcement_sent` | set MIROFISH_MEMORY_BACKEND=jsonl and stop using memory.db |
| S8 | Monitor sqlite write errors, lock contention, and migration support incidents wh | SRE | S7 | `monitor:sqlite_write_error_rate<0.1% for 24h` | switch backend selection back to jsonl without redeploy |
| S9 | Keep JSONL files in place until seven days pass without JSONL reads after cutove | DataPlatform | S8 | `wait_for:7d_no_jsonl_reads_after_cutover` | restore JSONL files from backup and switch backend back to j |
| S10 | Flip the default backend to sqlite for new runs after the notice period and stab | SRE | S8, S9 | `window:after_one_release_notice_period` | revert default backend to jsonl |

## SMT verification: 04-speed-tilted

- backend: `z3` (10 steps, 13 dep edges, 4 constraint edges)
- feasible: **True**
- witness ordering: `S1` → `S2` → `S3` → `S4` → `S5` → `S6` → `S7` → `S8` → `S9` → `S10`

## Chaos probe: 04-speed-tilted

- **fragility (overall)**: 0.071
- **fragility curve**: budget=1 → 0.083, budget=2 → 0.0
- **avg severity**: 2.07 (1=low … 4=critical)
- **rollback-failure rate**: 0.929 (13/14 probes)
- **recovery distribution**: recoverable_in_window=1, manual_ops=13
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 0.5
  - `S2` → 0.0
  - `S3` → 0.0
  - `S4` → 0.0
  - `S5` → 0.0

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
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
| S8, S9 | gate_violation | medium | NO | — | manual_ops |
| S2, S4 | gate_violation | medium | NO | — | manual_ops |

## Plan: 05-speed-tilted (weights (0.5, 0.5, 0.0))

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with sqlite3-only persistence,  | BackendOwner | — | `none` | Disable sqlite backend selection and route all persistence b |
| S2 | Add Agent backend selection in mirofish_lab/agent.py with backend="sqlite" suppo | BackendOwner | S1 | `none` | Revert Agent backend selection to jsonl-only default behavio |
| S3 | Add migration helper migrate_jsonl_to_sqlite() that imports every .mirofish_memo | BackendOwner | S1 | `wait_for:migration_helper_tests_pass` | Delete .mirofish_memory/memory.db and rerun import from JSON |
| S4 | Add concurrency, restart-persistence, and migration validation tests covering si | ConsumerSubsystem | S1, S2, S3 | `approval:release_manager` | Redeploy previous version and keep jsonl-only execution. |
| S5 | Create the SQLite schema and initial .mirofish_memory/memory.db in an off-hours  | DataPlatform | S3, S4 | `window:off_hours` | Drop the newly created SQLite database and keep JSONL backen |
| S6 | Keep JSONL as the default backend for one release while exposing sqlite only via | ProductPM | S2, S5 | `window:one_release` | Set MIROFISH_MEMORY_BACKEND=jsonl and keep sqlite opt-in onl |
| S7 | Enable sqlite opt-in for users who set MIROFISH_MEMORY_BACKEND=sqlite after migr | BackendOwner | S5, S6 | `wait_for:migration_validation_complete` | Switch MIROFISH_MEMORY_BACKEND back to jsonl and stop using  |
| S8 | Monitor sqlite opt-in traffic and keep JSONL files retained until 7 days pass wi | DataPlatform | S7 | `monitor:sqlite_busy_errors<1%` | Re-enable JSONL writes and pause SQLite writes until content |
| S9 | After one full release notice period and 24h of low sqlite write errors, flip th | SRE | S8 | `monitor:sqlite_write_error_rate<0.1% for 24h` | Revert default backend to jsonl without redeploying code. |
| S10 | After 7 days with no JSONL reads following cutover, remove legacy JSONL files or | DataPlatform | S9 | `wait_for:7d_no_jsonl_reads_after_cutover` | Restore JSONL files from backup and switch backend back to j |

## SMT verification: 05-speed-tilted

- backend: `z3` (10 steps, 14 dep edges, 4 constraint edges)
- feasible: **False**
Plan **infeasible**. Minimal conflicting set (2 edges):
- step `S5` depends_on `S3` (so `S3` must be earlier)
- Security's blocking constraint requires `S5` before `S3` (gate `wait_for:migration_reconciliation_verified`)

These edges form a cycle in the partial order. To fix: drop or weaken one of them, or insert an intermediate step that lets both orderings be satisfied.

## Chaos probe: 05-speed-tilted

- **fragility (overall)**: 0.5
- **fragility curve**: budget=1 → 0.583, budget=2 → 0.0
- **avg severity**: 2.5 (1=low … 4=critical)
- **rollback-failure rate**: 0.571 (7/14 probes)
- **recovery distribution**: recoverable_in_window=6, manual_ops=8
- **Achilles heel** (top 5 by per-step fragility):
  - `S1` → 1.0
  - `S6` → 1.0
  - `S2` → 0.5
  - `S3` → 0.5
  - `S4` → 0.5

| Targets | Failure type | Severity | RB holds | Blocked downstream | Recovery |
|---|---|---|---|---|---|
| S1 | gate_violation | high | yes | S2, S3, S4, S5, S6, S7 | recoverable_in_window |
| S2 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S3 | gate_violation | high | yes | S4, S5, S6, S7, S8, S9 | recoverable_in_window |
| S4 | gate_violation | high | yes | S5, S6, S7, S8, S9, S10 | recoverable_in_window |
| S5 | gate_violation | medium | NO | — | manual_ops |
| S6 | gate_violation | high | yes | S7, S8, S9, S10 | recoverable_in_window |
| S7 | gate_violation | medium | NO | — | manual_ops |
| S8 | gate_violation | medium | NO | — | manual_ops |
| S9 | gate_violation | medium | yes | S10 | recoverable_in_window |
| S1 | rollback_failure | critical | NO | S2, S3, S4, S5, S6, S7 | manual_ops |
| S2 | rollback_failure | medium | NO | — | manual_ops |
| S3 | rollback_failure | medium | NO | — | manual_ops |
| S4, S5 | gate_violation | medium | NO | — | manual_ops |
| S9, S5 | gate_violation | medium | NO | — | manual_ops |
