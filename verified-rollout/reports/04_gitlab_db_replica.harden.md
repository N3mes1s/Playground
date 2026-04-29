# Closed-Loop Hardening — 04_gitlab_db_replica

> Intent: validation/postmortems/intents/04_gitlab_db_replica.md · Threshold: 0.3 · Max iterations: 4 · Converged: no · Reason: iteration 1: no improvement (Δ 0.0) · Initial fragility: 0.5 · Final fragility: 0.5 · Model: gpt-5.4-mini

_Generated 2026-04-29T21:45:29Z_

## Convergence summary

- iterations run: 1 (after base)
- final reason: **iteration 1: no improvement (Δ 0.0)**
- fragility trajectory: 0.5 → 0.5

## Trajectory

| Iter | Stage | Steps | Fragility | Δ | SMT feasible | Top Achilles |
|---|---|---|---|---|---|---|
| 0 | base | 10 | 0.5 | — | Y | [['S1'], ['S2'], ['S3']] |
| 1 | hardened | 11 | 0.5 | 0.0 | Y | [['S1'], ['S2'], ['S3']] |

## Iteration 1 — diff

- step count: 10 -> 11
- added: ['S11']
- edits:
-   - S9.action: 'Remove temporary rebuild artifacts and a' → 'Verify replica health and stability once'
-   - S9.gate: 'wait_for:replication_healthy_and_stable' → 'monitor:replication_lag<1min'
-   - S9.rollback: 'Keep old artifacts until db2 is confirme' → 'Stop PostgreSQL on db2, restore the time'
-   - S9.observability: 'Artifact deletion status, remaining temp' → 'Lag samples, replay stalls, health-check'
-   - S6.action: 'Start PostgreSQL on db2 after base backu' → 'Re-seed db2 from db1 using pg_basebackup'
-   - S6.gate: 'monitor:replication_lag<=5min' → 'wait_for:pg_basebackup completion on db2'
-   - S6.rollback: 'Stop PostgreSQL on db2 and reinitialize ' → 'Discard the partial basebackup directory'
-   - S6.observability: 'Postgres startup success, replication st' → 'Basebackup progress/completion, disk IOP'
-   - S5.action: 'Remove the existing db2 data directory a' → 'Move the existing db2 data directory asi'
-   - S5.gate: 'wait_for:pg_basebackup completion on db2' → 'monitor:backup_dir_present_and_target_em'
-   - S5.rollback: 'Remove the incomplete data directory and' → 'Move the timestamped backup directory ba'
-   - S5.observability: 'Basebackup progress/completion, disk IOP' → 'Directory rename/move success, target pa'
-   - S7.action: 'Keep db2 out of any read/write traffic, ' → 'Start PostgreSQL on db2 after base backu'
-   - S7.gate: 'monitor:replication_lag=0' → 'monitor:replication_lag<=5min'
-   - S7.rollback: 'Leave db2 out of rotation and continue m' → 'Stop PostgreSQL on db2, restore the time'
-   - S7.observability: 'Replica lag, replay progress, and any at' → 'Postgres startup success, replication st'
-   - S10.action: 'Send the completion update that db2 is b' → 'Remove temporary rebuild artifacts and a'
-   - S10.gate: 'wait_for:replication caught up confirmat' → 'wait_for:replication_healthy_and_stable'
-   - S10.rollback: 'Issue a correction if sync status change' → 'Keep old artifacts until db2 is confirme'
-   - S10.observability: 'Customer/support update sent, final lag ' → 'Artifact deletion status, remaining temp'

## Final plan

{
  "summary": "Rebuild db2 from db1 with earlier identity/notification checks, split destructive work, explicit health gates, and safer rollback/integrity checks.",
  "steps": [
    {
      "id": "S1",
      "action": "Confirm the maintenance window is open, notify on-call/backup/customer-facing teams, assign the named escalation owner, and obtain second-engineer/observer acknowledgment before touching db2.",
      "owner": "SRE",
      "depends_on": [],
      "gate": "window:approved_maintenance_window",
      "rollback": "Send hold/completion notices and defer the rebuild to the next approved window.",
      "observability": "Acknowledgment receipts, change window status, named escalation owner assignment, and notification timestamps."
    },
    {
      "id": "S2",
      "action": "SSH to the target and perform explicit host identity checks for db2 using hostname, FQDN, and instance markers; both engineers must independently confirm the host is db2.",
      "owner": "SRE",
      "depends_on": [
        "S1"
      ],
      "gate": "approval:second_engineer",
      "rollback": "Exit the session immediately and reconnect only after re-verifying host identity out of band.",
      "observability": "Shell prompt, hostname/FQDN output, instance markers, and both engineers' confirmation."
    },
    {
      "id": "S3",
      "action": "Preserve audit logging for the session and preflight that no external dependency requires db2 as an access path during the rebuild.",
      "owner": "Security",
      "depends_on": [
        "S2"
      ],
      "gate": "approval:security",
      "rollback": "Pause the rebuild, restore logging if needed, and abort if an external dependency is found.",
      "observability": "Audit log continuity, dependency review result, and any security approval note."
    },
    {
      "id": "S4",
      "action": "Stop PostgreSQL on db2 only after host identity and approvals are confirmed.",
      "owner": "BackendOwner",
      "depends_on": [
        "S3"
      ],
      "gate": "monitor:postgres_down_and_no_writes",
      "rollback": "Start PostgreSQL on db2 again without wiping data.",
      "observability": "Service stop status, process exit, connection refusal on db2, and no writes accepted on db2."
    },
    {
      "id": "S5",
      "action": "Move the existing db2 data directory aside to a timestamped backup location, then verify the empty target path and free space before reseed.",
      "owner": "BackendOwner",
      "depends_on": [
        "S4"
      ],
      "gate": "monitor:backup_dir_present_and_target_empty",
      "rollback": "Move the timestamped backup directory back into place and restore db2's original data directory.",
      "observability": "Directory rename/move success, target path emptiness, backup directory checksum, and free-space headroom."
    },
    {
      "id": "S6",
      "action": "Re-seed db2 from db1 using pg_basebackup with throttling to avoid storage saturation; pause if disk or network pressure exceeds the safe budget.",
      "owner": "BackendOwner",
      "depends_on": [
        "S5"
      ],
      "gate": "wait_for:pg_basebackup completion on db2",
      "rollback": "Discard the partial basebackup directory, restore the timestamped backup directory if needed, and rerun pg_basebackup from db1.",
      "observability": "Basebackup progress/completion, disk IOPS, transfer rate, WAL fetch activity, and saturation alerts."
    },
    {
      "id": "S7",
      "action": "Start PostgreSQL on db2 after base backup completion and confirm streaming replication is running.",
      "owner": "BackendOwner",
      "depends_on": [
        "S6"
      ],
      "gate": "monitor:replication_lag<=5min",
      "rollback": "Stop PostgreSQL on db2, restore the timestamped backup directory if startup corrupted the reseed, and reinitialize from a fresh base backup if lag exceeds budget.",
      "observability": "Postgres startup success, replication state, initial lag trend, and replica connection logs."
    },
    {
      "id": "S8",
      "action": "Keep db2 out of any read/write traffic, failover, or backup-serving use while replication catches up, and verify the replica stays healthy before any later cleanup.",
      "owner": "BackendOwner",
      "depends_on": [
        "S7"
      ],
      "gate": "monitor:replication_lag=0",
      "rollback": "Leave db2 out of rotation, reapply traffic blocks if needed, and continue monitoring until caught up.",
      "observability": "Replica lag, replay progress, attempted routing to db2, and traffic-block enforcement."
    },
    {
      "id": "S9",
      "action": "Verify replica health and stability once lag reaches zero and stays healthy for the required observation period.",
      "owner": "SRE",
      "depends_on": [
        "S8"
      ],
      "gate": "monitor:replication_lag<1min",
      "rollback": "Stop PostgreSQL on db2, restore the timestamped backup directory if needed, and repeat the rebuild from db1.",
      "observability": "Lag samples, replay stalls, health-check success, and stability over time."
    },
    {
      "id": "S10",
      "action": "Remove temporary rebuild artifacts and any old replica data only after stable catch-up is confirmed.",
      "owner": "DataPlatform",
      "depends_on": [
        "S9"
      ],
      "gate": "wait_for:replication_healthy_and_stable",
      "rollback": "Keep old artifacts until db2 is confirmed healthy again; if cleanup removed the wrong path, restore from the timestamped backup directory.",
      "observability": "Artifact deletion status, remaining temporary files, backup-directory presence, and post-cleanup replica health."
    },
    {
      "id": "S11",
      "action": "Send the completion update that db2 is back in sync and hand ownership back to normal operations.",
      "owner": "ProductPM",
      "depends_on": [
        "S10"
      ],
      "gate": "wait_for:replication caught up confirmation",
      "rollback": "Issue a correction if sync status changes after the update.",
      "observability": "Customer/support update sent, final lag confirmation, and handoff acknowledgment."
    }
  ],
  "open_questions": [
    "Which specific approved maintenance window should be used for the rebuild start?",
    "Who is the named escalation owner for this event?",
    "Have on-call, backup owners, support, and customer-facing teams already been notified or must S1 perform those notifications?",
    "What exact host markers should the engineers use to confirm db2 identity?"
  ],
  "conflicts": [
    {
      "between": [
        "BackendOwner",
        "DataPlatform"
      ],
      "issue": "BackendOwner allows the standard rebuild sequence with stop/wipe/reseed, while DataPlatform/SRE/Security all require explicit host confirmation and two-person verification before destructive action; resolved by placing identity and approval gates before stop/wipe."
    },
    {
      "between": [
        "DataPlatform",
        "SRE"
      ],
      "issue": "DataPlatform/SRE require blocking destructive rebuild outside an approved maintenance window; resolved by making the maintenance window the first gate before any host access or destructive step."
    },
    {
      "between": [
        "Security",
        "ProductPM"
      ],
      "issue": "Security requires notifications and audit preservation before destructive work, while ProductPM requires support/customer comms and escalation ownership before start; resolved by a preflight step that bundles notifications, audit continuity, and escalation assignment before service stop."
    },
    {
      "between": [
        "ConsumerSubsystem",
        "BackendOwner"
      ],
      "issue": "ConsumerSubsystem wants db2 to keep serving the same replica interface, while BackendOwner requires db2 not be used for traffic until fully caught up; resolved by keeping db2 offline from client use during rebuild and only validating the interface after replication is healthy."
    }
  ]
}
