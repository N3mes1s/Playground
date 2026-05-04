# Migrate `.mirofish_memory/` from JSONL to SQLite for concurrent-safe access

## What

Replace the per-agent JSONL files under `.mirofish_memory/` with a single
SQLite database (`.mirofish_memory/memory.db`) accessed via a new
`SqliteMemory` backend in `mirofish_lab/memory.py`. The existing
`LocalMemory` class becomes a backwards-compat shim that reads any
JSONL files still present and writes new entries through the SQLite path.

## Why

- Concurrent runs of two experiments against the same repo (e.g. running
  `pr-review-rehearsal` and `blast-radius-prediction` in parallel
  during a CI check) currently corrupt the JSONL log because the file
  is opened in append mode without locking.
- We have no efficient way to query memory by tag or time range — current
  helpers walk the entire log linearly, which has become noticeable for
  agents that have accumulated >10k records across PRs in the same repo.
- Some users have asked for a single inspection point ("where do I look
  to see what reviewer X said about my repo last month?") — JSONL spread
  across files makes this awkward.

## Scope

- `mirofish_lab/memory.py` — add `SqliteMemory` class, keep `LocalMemory`
  signature unchanged.
- `mirofish_lab/agent.py` — Agent constructor opts into SQLite backend
  via a `backend="sqlite"` kwarg, defaulting to `"jsonl"` for now.
- All four experiments — no per-experiment changes required since they
  go through `Agent` which goes through the configured backend.
- A new env var `MIROFISH_MEMORY_BACKEND` selects the default: `jsonl`
  (current) or `sqlite` (new).
- A migration helper `mirofish_lab.memory.migrate_jsonl_to_sqlite()` that
  reads existing JSONL files in `.mirofish_memory/` and inserts their
  records into SQLite.

## Constraints

- **Backwards compatibility**: a user who pulls this branch must NOT
  immediately lose access to memory accumulated under JSONL. The default
  backend remains `jsonl` for one release. Users opt in via env var.
- **No external dependencies**: stdlib `sqlite3` only.
- **Persistent agent memory must survive restart**: failing to write to
  SQLite must not silently drop a record (instead, raise loud).
- **Cross-run readers**: any existing JSONL file under
  `.mirofish_memory/` must be importable into the SQLite store via
  `migrate_jsonl_to_sqlite()`.

## Out of scope

- Anything multi-machine or networked (still local-only).
- Vector embeddings / semantic search (separate experiment).
- Migrating away from the persona-name-as-table-key model.

## Affected subsystems

- `mirofish_lab` (storage + Agent integration)
- `pr-review-rehearsal` (only experiment using `persistent=True` today)
- `pre-flight-rehearsal`, `adversarial-security-sim`,
  `blast-radius-prediction` (use ephemeral memory; will inherit the
  default backend env var if/when they enable persistence)

## What success looks like

A user setting `MIROFISH_MEMORY_BACKEND=sqlite` and re-running an
experiment they had previously run under JSONL sees their old reviewer
comments in the new SQLite store; concurrent runs no longer corrupt the
log; and `sqlite3 .mirofish_memory/memory.db ".tables"` reveals a single
inspectable table.
