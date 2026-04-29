# Add per-finding history log to `adversarial-security-sim`

## What

Persist each finding's debate transcript and verdict to a structured
JSONL log under `.mirofish_memory/security/<source-stem>.jsonl` so
re-runs of the same audit report can:

1. Compare verdicts across runs (did the model flip on a finding?).
2. Show "verdict drift": a finding marked NEEDS_VALIDATION two runs
   ago but now FALSE_POSITIVE is interesting.
3. Aggregate: across N audit reports run through the simulator, what
   are the most common false-positive patterns?

## Why

- Single-run output is a snapshot; the value of repeated runs is
  comparison.
- Aggregated FP patterns across reports are valuable feedback for
  upstream scanners (e.g. `recursive-lm-security-audit`'s prompt
  tuning).
- Cheap: structured append-only log; no schema migration.

## Scope

- `adversarial-security-sim/cli.py`: at end of each finding's debate,
  append a record with `{source, finding_id, severity, verdict,
  triager_sha256, maintainer_sha256, model, timestamp}`.
- New `adversarial-security-sim/history.py` with a
  `verdict_drift(source, finding_id)` helper that walks the log and
  shows verdicts across runs.
- Optional flag `--show-drift` on the CLI prints the drift summary
  before the report.

## Constraints

- **Append-only**: never overwrite past records.
- **Privacy**: do not log full finding bodies — store hashes of the
  agent outputs so we can detect "same vs different content" without
  hoarding text.
- **Compatible with the new SQLite memory backend**: if/when
  `mirofish_lab` switches storage backend (see
  `intent_sqlite_memory_migration.md`), this log moves to the same
  store.

## Out of scope

- Cross-source aggregation UI.
- Auto-suggesting prompt changes upstream.

## Affected stakeholders

- `adversarial-security-sim` (the change)
- `mirofish_lab` memory layer (cross-coupling)
- `recursive-lm-security-audit` (consumes the drift signal eventually)
