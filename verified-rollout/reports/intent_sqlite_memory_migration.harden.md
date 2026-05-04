# Closed-Loop Hardening — intent_sqlite_memory_migration

> Intent: fixtures/intent_sqlite_memory_migration.md · Threshold: 0.3 · Max iterations: 4 · Converged: no · Reason: iteration 1: hardened plan infeasible by Z3 (unsat core size 2) · Initial fragility: 0.467 · Final fragility: 0.473 · Model: gpt-5.4-mini

_Generated 2026-04-29T21:43:46Z_

## Convergence summary

- iterations run: 1 (after base)
- final reason: **iteration 1: hardened plan infeasible by Z3 (unsat core size 2)**
- fragility trajectory: 0.467 → 0.473

## Trajectory

| Iter | Stage | Steps | Fragility | Δ | SMT feasible | Top Achilles |
|---|---|---|---|---|---|---|
| 0 | base | 10 | 0.467 | — | N | [['S1'], ['S2'], ['S3']] |
| 1 | hardened | 11 | 0.473 | 0.006 | N | [['S1a'], ['S1b'], ['S2a']] |

## Iteration 1 — diff

- step count: 10 -> 11
- added: ['S1a', 'S1b', 'S2a', 'S2b', 'S4a', 'S4b']
- removed: ['S1', 'S10', 'S2', 'S4', 'S9']
- edits:
-   - S5.action: 'Release the sqlite backend and LocalMemo' → 'Run bounded backfill in production-ready'
-   - S5.gate: 'approval:release-owner' → 'monitor:disk_io_utilization<70%'
-   - S5.rollback: 'Set MIROFISH_MEMORY_BACKEND=jsonl and di' → 'Pause migration, stop SQLite writes, and'
-   - S5.observability: 'Check opt-in usage, backend selection co' → 'Watch disk IO, batch latency, replicatio'
-   - S5.depends_on: ['S4'] → ['S4a']
-   - S7.action: 'Run bounded backfill in production-ready' → 'Wait for a quiet period with no writes f'
-   - S7.gate: 'monitor:disk_io_utilization<70%' → 'wait_for:7d_no_write_activity'
-   - S7.rollback: 'Pause migration, stop SQLite writes, and' → 'Restore JSONL files from backup and resu'
-   - S7.observability: 'Watch disk IO, batch latency, replicatio' → 'Confirm absence of writes, backup integr'
-   - S7.depends_on: ['S5'] → ['S6']
-   - S8.action: 'Validate stable read/write behavior unde' → 'After notice, approvals, and a safe rele'
-   - S8.gate: 'monitor:error_rate<0.1% for 24h' → 'window:>=1 release notice'
-   - S8.rollback: 'Switch backend back to JSONL and keep ex' → 'Revert default backend to jsonl and keep'
-   - S8.observability: 'Track write/read error rate, latency, an' → 'Monitor default-selection telemetry, cus'
-   - S8.depends_on: ['S7'] → ['S4b', 'S6', 'S7']
-   - S6.action: 'Publish migration guidance and support r' → 'Validate stable read/write behavior unde'
-   - S6.gate: 'approval:support' → 'monitor:error_rate<0.1% for 24h'
-   - S6.rollback: 'Remove SQLite opt-in messaging until mig' → 'Switch backend back to JSONL and keep ex'
-   - S6.observability: 'Confirm docs/release notes are live and ' → 'Track write/read error rate, latency, an'
-   - S3.action: 'Build migrate_jsonl_to_sqlite() to impor' → 'Test migration helper on existing repos '

## Final plan

{
  "summary": "Ship SQLite memory backend with JSONL shim, migrate existing logs safely, and keep JSONL default until the approved cutover window.",
  "steps": [
    {
      "id": "S1",
      "action": "Implement SqliteMemory in mirofish_lab/memory.py with stdlib sqlite3, keep LocalMemory signature unchanged, and add Agent backend selection via backend kwarg plus MIROFISH_MEMORY_BACKEND defaulting to jsonl.",
      "owner": "BackendOwner",
      "depends_on": [],
      "gate": "none",
      "rollback": "redeploy_previous",
      "observability": "Unit tests for API stability, backend selection, and loud errors on SQLite write failures."
    },
    {
      "id": "S2",
      "action": "Add SQLite schema creation path and indexes for .mirofish_memory/memory.db, ensuring the schema is created only when the backend is explicitly sqlite.",
      "owner": "DataPlatform",
      "depends_on": [
        "S1"
      ],
      "gate": "window:off-hours",
      "rollback": "Drop newly created SQLite tables and revert to JSONL-only path",
      "observability": "Track schema creation success, table/index presence, and any startup failures."
    },
    {
      "id": "S3",
      "action": "Build migrate_jsonl_to_sqlite() to import all .mirofish_memory/*.jsonl records into SQLite in bounded batches, preserving audit fields and handling any stored-secret redaction or rotation before import.",
      "owner": "Security",
      "depends_on": [
        "S2"
      ],
      "gate": "approval:security",
      "rollback": "Delete imported rows from memory.db and rerun JSONL-backed access",
      "observability": "Watch batch duration, import counts, audit report generation, and any secret-handling warnings."
    },
    {
      "id": "S4",
      "action": "Test migration helper on existing repos and validate import correctness, reversibility, and quiet-period behavior without removing legacy JSONL files.",
      "owner": "ConsumerSubsystem",
      "depends_on": [
        "S3"
      ],
      "gate": "wait_for:migration_tests_pass",
      "rollback": "restore JSONL-only LocalMemory read/write path",
      "observability": "Compare imported record counts, sample queries by tag/time, and verify no legacy data loss."
    },
    {
      "id": "S5",
      "action": "Release the sqlite backend and LocalMemory shim behind opt-in only, leaving JSONL as the default backend for one release.",
      "owner": "BackendOwner",
      "depends_on": [
        "S4"
      ],
      "gate": "approval:release-owner",
      "rollback": "Set MIROFISH_MEMORY_BACKEND=jsonl and disable sqlite default",
      "observability": "Check opt-in usage, backend selection correctness, and error rates on sqlite writes."
    },
    {
      "id": "S6",
      "action": "Publish migration guidance and support runbook for existing .mirofish_memory users, including how to opt in, migrate, and inspect memory.db.",
      "owner": "ProductPM",
      "depends_on": [
        "S5"
      ],
      "gate": "approval:support",
      "rollback": "Remove SQLite opt-in messaging until migration docs are published",
      "observability": "Confirm docs/release notes are live and support has an escalation owner."
    },
    {
      "id": "S7",
      "action": "Run bounded backfill in production-ready conditions only when IO is healthy, with monitoring on disk utilization and migration throughput.",
      "owner": "DataPlatform",
      "depends_on": [
        "S5"
      ],
      "gate": "monitor:disk_io_utilization<70%",
      "rollback": "Pause migration, stop SQLite writes, and continue on JSONL backend",
      "observability": "Watch disk IO, batch latency, replication lag, and write error counts."
    },
    {
      "id": "S8",
      "action": "Validate stable read/write behavior under load for 24h after opt-in rollout, keeping JSONL fallback available if SQLite misbehaves.",
      "owner": "SRE",
      "depends_on": [
        "S7"
      ],
      "gate": "monitor:error_rate<0.1% for 24h",
      "rollback": "Switch backend back to JSONL and keep existing memory.db intact",
      "observability": "Track write/read error rate, latency, and any corruption or lock contention signals."
    },
    {
      "id": "S9",
      "action": "Wait for a quiet period with no writes for 7 days before removing legacy JSONL files, and keep backups for restoration.",
      "owner": "DataPlatform",
      "depends_on": [
        "S8"
      ],
      "gate": "wait_for:7d_no_write_activity",
      "rollback": "Restore JSONL files from backup and resume JSONL reads",
      "observability": "Confirm absence of writes, backup integrity, and post-removal query success."
    },
    {
      "id": "S10",
      "action": "After notice, approvals, and a safe release window, flip the default backend to sqlite while preserving env-var override for jsonl.",
      "owner": "ProductPM",
      "depends_on": [
        "S6",
        "S8",
        "S9"
      ],
      "gate": "window:>=1 release notice",
      "rollback": "Revert default backend to jsonl and keep env-var opt-in only",
      "observability": "Monitor default-selection telemetry, customer support volume, and any regression in experiment runs."
    }
  ],
  "open_questions": [
    "Which person or team owns the release-owner approval gate?",
    "What exact off-hours window should be used for initial schema creation?",
    "What secret rotation/redaction rules apply to persisted memory fields before import?",
    "What constitutes 'existing repos' for migration testing and how many must be covered?",
    "Who signs off that the one-release customer notice has been sent?"
  ],
  "conflicts": [
    {
      "between": [
        "BackendOwner",
        "SRE"
      ],
      "issue": "BackendOwner requires the default backend to stay jsonl for one release, while SRE requires gating the cutover on stable behavior before changing defaults. Resolved by keeping jsonl default through the opt-in phase and deferring any default flip until post-verification."
    },
    {
      "between": [
        "BackendOwner",
        "Security"
      ],
      "issue": "BackendOwner wants the sqlite schema path available before default reads it, but Security requires compliance review before enabling sqlite default. Resolved by building schema and opt-in backend first, then delaying any default flip until compliance approval."
    },
    {
      "between": [
        "BackendOwner",
        "ProductPM"
      ],
      "issue": "BackendOwner's rollout plan allows opt-in sqlite before default change, while ProductPM requires one release of announcement before externally visible default change. Resolved by shipping opt-in now and scheduling default flip only after notice."
    },
    {
      "between": [
        "BackendOwner",
        "ConsumerSubsystem"
      ],
      "issue": "BackendOwner wants jsonl as the default for one release, and ConsumerSubsystem also requires sqlite opt-in only until migration helper is tested. These align on the same path; no adjustment needed beyond holding the default."
    },
    {
      "between": [
        "DataPlatform",
        "SRE"
      ],
      "issue": "DataPlatform asks to keep JSONL files until 7 days of quiet activity, while SRE requires stable load validation and reversible migration steps. Resolved by keeping JSONL files through validation and only removing them after the quiet period passes."
    },
    {
      "between": [
        "DataPlatform",
        "Security"
      ],
      "issue": "DataPlatform requires bounded-batch backfill and schema creation in an off-hours window, while Security requires secret handling changes before JSONL import. Resolved by sequencing secret handling and then running bounded migration under off-hours/IO-safe conditions."
    },
    {
      "between": [
        "DataPlatform",
        "ProductPM"
      ],
      "issue": "DataPlatform wants quiet-period validation before deleting JSONL, while ProductPM wants migration guidance available for users during the rollout. Resolved by publishing guidance before cutover and retaining JSONL until quiet-period validation completes."
    },
    {
      "between": [
        "DataPlatform",
        "ConsumerSubsystem"
      ],
      "issue": "DataPlatform's migration helper must import existing JSONL files, while ConsumerSubsystem requires a shim that can still read legacy JSONL. Resolved by implementing import plus shim support in parallel and not deleting JSONL until later."
    },
    {
      "between": [
        "SRE",
        "ProductPM"
      ],
      "issue": "SRE prohibits rollout during incident windows or Friday afternoon and ProductPM prohibits rollout during active launch or major customer events. Resolved by making the cutover contingent on both safe timing rules being satisfied."
    },
    {
      "between": [
        "SRE",
        "ConsumerSubsystem"
      ],
      "issue": "SRE wants a fallback to JSONL if SQLite is not ready, and ConsumerSubsystem also requires JSONL default for one release. These are compatible and reinforced in the plan."
    },
    {
      "between": [
        "Security",
        "ProductPM"
      ],
      "issue": "Security requires compliance review and support readiness, while ProductPM requires support briefing and release-notice timing. Resolved by placing docs, support briefing, and compliance before default flip."
    }
  ]
}
