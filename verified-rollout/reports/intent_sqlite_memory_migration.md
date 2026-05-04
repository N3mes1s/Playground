# Verified Rollout — intent_sqlite_memory_migration

> Intent: fixtures/intent_sqlite_memory_migration.md · Stakeholders: 6 · Constraints: 25 · Pareto plans: balanced, conservative, aggressive · Chaos samples per plan: 3 · Recommendation: balanced · Model: gpt-5.4-mini

_Generated 2026-04-29T19:22:33Z_

## Recommendation

**balanced** — Picked 'balanced' as Pareto-optimal: fragility=0.667, coverage=1.0, steps=10, avg_severity=2.33.

## Scoreboard

| Plan | Steps | DAG | Coverage | Fragility | Severity | RB-fail | Approval | Monitor |
|---|---|---|---|---|---|---|---|---|
| balanced | 10 | Y | 1.0 | 0.667 | 2.33 | 0.333 | 2 | 2 |
| conservative | 12 | Y | 1.0 | 1.0 | 2.67 | 0.0 | 3 | 2 |
| aggressive | 8 | Y | 1.0 | 1.0 | 2.33 | 0.0 | 2 | 2 |

## Plan: balanced

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with stdlib sqlite3, schema creation, lou | BackendOwner | — | `wait_for:SqliteMemory implementation merged and exercised in CI` | redeploy_previous |
| S2 | Add Agent backend selection with backend='sqlite' support and MIROFISH_MEMORY_BACKEND defa | BackendOwner | S1 | `approval:security` | restore JSONL-only writes and disable sqlite backend selecti |
| S3 | Implement LocalMemory as a compatibility shim that reads legacy JSONL files and writes new | ConsumerSubsystem | S1, S2 | `wait_for:migration_helper_merged` | switch LocalMemory back to JSONL append-only behavior |
| S4 | Add migrate_jsonl_to_sqlite() to import existing .mirofish_memory/*.jsonl into memory.db i | DataPlatform | S1, S3 | `window:off-hours` | stop migration, keep JSONL files as source of truth, and del |
| S5 | Add a cutover test proving prior JSONL memory is visible through SQLite and migration is r | ConsumerSubsystem | S4 | `approval:release_owner` | redeploy_previous |
| S6 | Run migration validation on existing repos, including import verification and cleanup safe | SRE | S4, S5 | `wait_for:migration_validation_pass` | Delete memory.db and restore original jsonl files from backu |
| S7 | Enable opt-in SQLite backend for canary users while keeping jsonl as the default backend. | SRE | S2, S6 | `monitor:sqlite_write_error_rate<0.1%` | Switch backend to jsonl and stop writing memory.db |
| S8 | Monitor migration and runtime health, including sqlite write failures, replication lag, an | DataPlatform | S7 | `monitor:replication_lag<30s` | pause import, drain writes, and fall back to JSONL until lag |
| S9 | Keep JSONL files in place after successful import until the quiet period has passed with n | DataPlatform | S6, S7 | `wait_for:7d_no_write_to_jsonl` | restore JSONL files from backup and resume reads from JSONL  |
| S10 | After one release grace period and release-owner approval, flip the default backend to sql | ProductPM | S7, S8, S9 | `window:one_release_grace_period` | set MIROFISH_MEMORY_BACKEND=jsonl and redeploy_previous |

## Verification: balanced

- DAG: **pass**
- Unreachable steps: none
- Invalid gates: none
- Blocking-constraint coverage: 23/23 (ratio 1.00)
- Overall: PASS

## Chaos probe: balanced

- **fragility**: 0.667 (0 = robust, 1 = single failure cascades to all downstream)
- **avg severity**: 2.33 (scale: 1 low, 2 medium, 3 high, 4 critical)
- **rollback-failure rate**: 0.333 (0/3 probes had broken rollback chain)

| Target | Severity | Rollback holds | Blocked downstream | Recovery |
|---|---|---|---|---|
| S2 (Add Agent backend selection with backend) | high | yes | S3, S4, S5, S6, S7, S8 | S2 is blocked only at the approval:security gate, so no code rollback is require |
| S4 (Add migrate_jsonl_to_sqlite() to import ) | medium | yes | S5, S6, S7, S8, S9, S10 | S4 is blocked at the gate:window:off-hours, so the migration helper has not run  |
| S6 (Run migration validation on existing rep) | medium | NO | — | unspecified |

## Plan: conservative

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with sqlite3-only writes, schema creation | BackendOwner | — | `wait_for:SqliteMemory implementation merged and exercised in CI` | revert SqliteMemory implementation to previous memory backen |
| S2 | Add the Agent backend selector and MIROFISH_MEMORY_BACKEND plumbing, keeping jsonl as the  | BackendOwner | S1 | `approval:release-owner` | set Agent default backend and MIROFISH_MEMORY_BACKEND handli |
| S3 | Implement LocalMemory as a compatibility shim that reads legacy JSONL records and writes n | ConsumerSubsystem | S2 | `wait_for:migration_helper_merged` | switch LocalMemory back to JSONL append-only behavior |
| S4 | Add migrate_jsonl_to_sqlite() to import existing .mirofish_memory/*.jsonl into memory.db i | DataPlatform | S1, S3 | `wait_for:migration helper available and verified on existing repos` | stop migration, keep JSONL files as source of truth, and del |
| S5 | Run initial SQLite schema creation and any ALTER-style changes only during an off-hours ma | DataPlatform | S1 | `window:off-hours` | revert to JSONL backend and defer schema changes to the next |
| S6 | Seed a canary repository using sqlite backend and verify prior JSONL memory is visible in  | ConsumerSubsystem | S2, S4, S5 | `monitor:sqlite_write_error_rate<0.1%` | Switch backend to jsonl and stop writing memory.db |
| S7 | Enable small-batch JSONL-to-SQLite backfill for existing repos while keeping JSONL as the  | DataPlatform | S4, S5 | `monitor:iops<80%` | stop migration, keep JSONL files as source of truth, and del |
| S8 | Hold JSONL files in place after successful import and do not delete legacy files until the | DataPlatform | S7 | `wait_for:7d_no_write_to_jsonl` | restore JSONL files from backup and resume reads from JSONL  |
| S9 | Complete security and compliance review for persistent SQLite memory writes and DB file ac | Security | S1, S2 | `approval:compliance` | ship sqlite only as opt-in behind MIROFISH_MEMORY_BACKEND |
| S10 | Brief support and assign an escalation owner for migration failures and rollback handling. | ProductPM | S4, S6 | `approval:support_lead` | redeploy_previous |
| S11 | Send customer notice and deprecation communication before any future default backend flip. | ProductPM | S9, S10 | `wait_for:customer_notice_sent` | keep MIROFISH_MEMORY_BACKEND default at jsonl for the releas |
| S12 | Keep jsonl as the default backend for one release while sqlite remains opt-in only. | SRE | S2, S9, S11 | `window:one_release_grace_period` | Set MIROFISH_MEMORY_BACKEND=jsonl and disable sqlite opt-in |

## Verification: conservative

- DAG: **pass**
- Unreachable steps: none
- Invalid gates: none
- Blocking-constraint coverage: 23/23 (ratio 1.00)
- Overall: PASS

## Chaos probe: conservative

- **fragility**: 1.0 (0 = robust, 1 = single failure cascades to all downstream)
- **avg severity**: 2.67 (scale: 1 low, 2 medium, 3 high, 4 critical)
- **rollback-failure rate**: 0.0 (0/3 probes had broken rollback chain)

| Target | Severity | Rollback holds | Blocked downstream | Recovery |
|---|---|---|---|---|
| S4 (Add migrate_jsonl_to_sqlite() to import ) | high | yes | S6, S7, S8, S10, S11, S12 | S4 failing at wait_for:migration helper available and verified on existing repos |
| S5 (Run initial SQLite schema creation and a) | medium | yes | S6, S7, S8, S10, S11, S12 | S5 is the off-hours maintenance-window gate for initial SQLite schema creation.  |
| S3 (Implement LocalMemory as a compatibility) | high | yes | S4, S6, S7, S8, S10, S11 | S3 failing at wait_for:migration_helper_merged blocks the migration helper path  |

## Plan: aggressive

| # | Action | Owner | Deps | Gate | Rollback |
|---|---|---|---|---|---|
| S1 | Implement SqliteMemory in mirofish_lab/memory.py with sqlite3-only persistence, loud write | BackendOwner | — | `window:off-hours` | redeploy_previous |
| S2 | Add Agent backend selection via backend="sqlite" and MIROFISH_MEMORY_BACKEND, keeping json | BackendOwner | S1 | `wait_for:SqliteMemory implementation merged and exercised in CI` | revert default backend to jsonl |
| S3 | Build migration helper migrate_jsonl_to_sqlite() to import existing .mirofish_memory/*.jso | DataPlatform | S1 | `monitor:iops<80%` | stop migration, keep JSONL files as source of truth, and del |
| S4 | Exercise migration on existing repos and validate cutover: imported JSONL appears in SQLit | ConsumerSubsystem | S2, S3 | `wait_for:migration helper available and verified on existing repos` | switch LocalMemory back to JSONL append-only behavior |
| S5 | Run security/compliance review for the SQLite persistence path and DB access handling befo | Security | S1, S2, S3 | `approval:compliance` | ship sqlite only as opt-in behind MIROFISH_MEMORY_BACKEND |
| S6 | Release opt-in SQLite backend behind the env var for canary users, keeping JSONL default a | ProductPM | S4, S5 | `approval:support_lead` | redeploy_previous |
| S7 | Monitor canary and migration health, including sqlite write error rate, replication lag, a | SRE | S6 | `monitor:sqlite_write_error_rate<0.1%` | Switch backend to jsonl and stop writing memory.db |
| S8 | After one release grace period and customer notice, flip the default backend to sqlite whi | ProductPM | S7 | `window:one_release_grace_period` | set MIROFISH_MEMORY_BACKEND=jsonl and redeploy_previous |

## Verification: aggressive

- DAG: **pass**
- Unreachable steps: none
- Invalid gates: none
- Blocking-constraint coverage: 23/23 (ratio 1.00)
- Overall: PASS

## Chaos probe: aggressive

- **fragility**: 1.0 (0 = robust, 1 = single failure cascades to all downstream)
- **avg severity**: 2.33 (scale: 1 low, 2 medium, 3 high, 4 critical)
- **rollback-failure rate**: 0.0 (0/3 probes had broken rollback chain)

| Target | Severity | Rollback holds | Blocked downstream | Recovery |
|---|---|---|---|---|
| S4 (Exercise migration on existing repos and) | medium | yes | S6, S7, S8 | S4 is blocked at gate wait_for:migration helper available and verified on existi |
| S3 (Build migration helper migrate_jsonl_to_) | high | yes | S4, S5, S6, S7, S8 | S3 fails before the migration helper is considered safe under its gate monitor:i |
| S6 (Release opt-in SQLite backend behind the) | medium | yes | S7, S8 | S6 is blocked at gate approval:support_lead, so the opt-in canary release cannot |
