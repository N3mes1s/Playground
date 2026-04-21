# Operations

How to actually *run* `ods`: in CI, locally, under a budget, with
observability, and what the historical dogfood runs taught us.

---

## Binaries

`ods` ships as a single static binary per target triple. The
`.github/workflows/release.yml` workflow builds all five on tag push:

| Triple                         | Runner                    | Notes |
|--------------------------------|---------------------------|-------|
| `x86_64-unknown-linux-musl`    | `ubuntu-latest` + zig     | primary, fully static |
| `aarch64-unknown-linux-musl`   | `ubuntu-latest` + zig     | fully static |
| `x86_64-apple-darwin`          | cross from ubuntu + zig   | eBPF/perf paths disabled |
| `aarch64-apple-darwin`         | cross from ubuntu + zig   | eBPF/perf paths disabled |
| `x86_64-pc-windows-gnu`        | cross from ubuntu + zig   | best-effort, no perf |

The musl builds are the blessed path. `ldd target/.../ods` should print
`not a dynamic executable` — that's what makes "curl into CI, run" work
on any distro.

### Local build

```bash
# Dev build (libc, native target)
cargo build --release --bin ods

# Musl static build (requires zig + cargo-zigbuild)
cargo zigbuild --release --target x86_64-unknown-linux-musl --bin ods
```

---

## CI integration (one-shot action)

The blessed entry point for unsolicited OSS PRs is the one-shot action
mode. Example workflow for a target repo:

```yaml
name: ods
on:
  schedule:
    - cron: "0 4 * * 1"   # Monday 04:00 UTC
  workflow_dispatch:

jobs:
  ods:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: install ods
        run: |
          curl -fsSL -o /usr/local/bin/ods \
            https://github.com/n3mes1s/playground/releases/download/ods-v0.1/ods-x86_64-unknown-linux-musl
          chmod +x /usr/local/bin/ods
      - name: run ods
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN:      ${{ secrets.GITHUB_TOKEN }}
        run: |
          ods ci action \
            --mode ci \
            --wall-cap 45m \
            --spend-cap 10.00
```

### What "mode ci" does

- Enforces `wall-cap` and `spend-cap` at every stage transition.
- On exhaustion, writes a partial-result artefact under `.ods/runs/<id>/`
  and exits 0 — a graceful degradation, not a CI failure.
- Opens a PR only if `ZeroDiffGate::evaluate` returns `Pass` **and**
  `determinism_ok = true`.
- Skips the PR step if any gate fails; the run is still persisted for
  `ods explain`.

### GitHub App mode (serve)

For interactive "run when asked" workflows:

```bash
ods ci serve --port 8787
```

See [`integrations.md`](integrations.md#webhook-server) for the webhook
shape. Required env:

- `ODS_APP_ID`
- `ODS_APP_PRIVATE_KEY_PEM` (PEM contents, not a path)
- `ODS_APP_INSTALLATION_ID`
- `ODS_WEBHOOK_SECRET`

Users trigger a run by commenting `/ods optimize` on an issue or PR in an
allowlisted repo. The webhook queues the event; a worker clones, runs,
and opens a sibling PR.

---

## Budgets and autonomy

Every run carries a `Mode`:

```rust
pub enum Mode {
    Dev,
    Ci { wall_cap: Duration, spend_cap: f64 },
}
```

- **Dev** — no caps. Useful for local reproduction and deep debugging.
- **Ci** — checked at every `LoopStage` transition and after every
  specialist finish in the race.

### How spend accounting works

Each Anthropic response returns `usage.input_tokens` and
`usage.output_tokens`. `LoopStats.estimated_cost_usd(model)` multiplies
by the per-model rate, and the orchestrator accumulates into
`Run.spent_usd` after each specialist's conversation terminates.

**Known limitation**: enforcement is per-stage, not per-token. A
specialist that takes 90 seconds and 2M tokens will run to completion
even if the budget would have been exhausted mid-turn. In a recent
dogfood on `tokei` with `--spend-cap 6.00`, actual spend was **$6.65** —
a 10% overshoot. The budget is a soft ceiling, not a hard one.

### Wall-clock accounting

Wall is measured from `Run::started_at` against `wall_cap`. On exhaustion
the orchestrator sets `run.status = timed_out` and emits a partial
artefact. The in-flight specialist subprocess is SIGTERM'd; the worktree
is cleaned up by the next `cargo clean` or `WorktreeHandle::drop`.

---

## Observability

### Persistent state

Everything lives under `.ods/` in the working directory:

```
.ods/
├── runs.db                # SQLite — runs + run_events
├── runs/<run-id>.json     # Full artefact per run
└── runs/<run-id>/
    ├── pre-profile.json
    ├── post-profile.json
    ├── pre-bench.json
    ├── post-bench.json
    ├── patch.diff
    ├── flame.svg          # When flame capture succeeded
    └── gate.json          # ZeroDiffGate::evaluate output
```

`runs.db` is the source of truth; JSON files are convenience dumps for
human inspection. Schema:

```sql
CREATE TABLE runs (
    id          TEXT PRIMARY KEY,
    repo        TEXT, target TEXT,
    status      TEXT,         -- pending | running | completed | timed_out | failed
    started_at  INTEGER, finished_at INTEGER,
    spent_usd   REAL,
    artifact_path TEXT
);
CREATE TABLE run_events (
    run_id      TEXT REFERENCES runs(id),
    stage       TEXT,         -- TargetSelect, Profile, ..., Harvest
    ts          INTEGER,
    payload     TEXT          -- JSON blob per event shape
);
```

### `ods explain`

```bash
ods explain <run-id>
ods explain <run-id> --timeline
ods explain --batch <batch-id>
```

- Plain mode renders the PR body as text: speedup, bench table, syscall
  delta, applied recipes, gate verdict.
- `--timeline` prints one line per `run_events` row, with stage,
  timestamp (relative to run start), and payload. Useful when a run
  silently went sideways.
- `--batch` summarises a scheduler batch (`ods optimize`) including all
  child runs.

### Logging

`tracing` with `EnvFilter`; set `RUST_LOG=ods=debug` for per-stage
transitions, `RUST_LOG=ods::anthropic=debug` for request/response body
keys (PII-safe; we log the shape, not the content).

### Observed failure modes

From the dogfood log:

- **CI overlap after race win.** Host too noisy; rerun-N gate catches
  it, PR is withheld. Mitigation: run with `ODS_CPU_PIN=3` on a
  dedicated core, verify `cpu_governor=performance`.
- **`cargo-fuzz` missing.** Fuzz step becomes a no-op (returns an empty
  `FuzzReport`). The gate downgrades that arm to "soft-pass" and the
  PR body notes the absence.
- **Bench scaffolder produces a no-op bench.** The specialist's job is
  to rewrite `b.iter(...)` with a realistic fixture; if it doesn't, the
  bench returns pure noise and the verdict is rejected. This is working
  as intended — we'd rather see "CI overlap" than a fake speedup.
- **Explorer proposes 0 recipes.** Model judgment varies. Retry, or
  raise `--budget-usd`, or narrow with `--language rust` so the survey
  stays focused.

---

## Dogfood log

Running record of what we've tried and what the tool taught us.

### Self-host (2026-04-17)

- Target: this workspace's own `ods_recipes::score::score_recipes`.
- Result: specialist race landed a `fastpath-early-return` style patch,
  verdict accepted at 1.8× lower bound, PR withheld (self-host, no PR
  target).
- Harvest produced `auto-rust-fastpath-ods_recipes-score-score_recipes`;
  Generalizer phase-2 produced `general-rust-early-return-scored-iter`
  linked via `generalized_from` / `generalized_as`.

### `N3mes1s/claude-teleport-analyzer` (2026-04-18)

- One target picked autonomously by `ods optimize`.
- `Planner` retrieved 2 seed recipes plus 1 Candidate from the earlier
  self-host harvest.
- Race ran 3 specialists in parallel; `AllocReducer` won with a
  `smallvec`-substitution patch, 2.1× lower bound.
- PR opened successfully; target CI passed.
- Lesson: retrieved Candidate *didn't* apply cleanly (its regex trigger
  was too narrow) — it left a `NegativeRecord` behind. The Candidate
  promotion stayed unchanged (we don't demote on abstain, only auto-retire
  Hypothesized).

### `XAMPPRocky/tokei` (2026-04-18)

- Spend cap $6.00; actual $6.65 — **10% overshoot**, documented limitation.
- Discovered a `chars().count()` smell via anti-pattern scan; the target
  had no matching recipe in the corpus.
- Explorer run afterward proposed 3 Hypothesized recipes including one
  for `chars().count()` vs `chars().take(n)` bounded iteration.
- Lesson: anti-patterns surface *targets*, Explorer proposes *patterns*.
  They don't need to be the same entity.

### First Explorer dogfood (2026-04-19)

- `ods explore . --budget-usd 3`, empty output.
- Root cause: parser over-consumed on `{example}` prose in the final
  text block.
- Fix iteration 1 (prompt engineering) — partial; JSON still had
  trailing commas sometimes.
- Fix iteration 2 (Anthropic structured outputs with
  `output_config.format.json_schema.schema`) — reliable. Three
  subsequent runs all returned either valid `{"recipes":[...]}` or
  empty `{"recipes":[]}` with no parser errors.
- Lesson: grammar-constrained decoding beats prompt engineering for
  structured-output reliability. Always.

### "I still see only hash map optimization" (2026-04-19)

- Observed: corpus skew — specialists could only find
  HashMap/Vec-style allocation wins because that's all the seed
  corpus covered.
- Fix: dispatched a research agent (WebSearch + WebFetch) for
  uncovered areas and translated findings into 12 new Seed recipes:
  SIMD, branch prediction (`#[cold]`), branchless select, portable
  SIMD reductions, async (`FuturesUnordered`, `spawn_blocking`), I/O
  (`io_uring`), numeric (FMA, loop tiling), layout (NonZero niche),
  compile-time (const fn + build.rs lookup tables).
- Lesson: the corpus is the product. Without diverse recipes, agents
  have nothing to match against and fall back to shallow pattern
  replacement.

---

## Operator checklist

Pre-run:

- [ ] `cpufreq` governor is `performance` (check with `ods` soft-warning
      from `assert_determinism`).
- [ ] `kernel.perf_event_paranoid <= 2` if you want `perf stat`
      counters.
- [ ] `ANTHROPIC_API_KEY` exported.
- [ ] `GITHUB_TOKEN` or the three `ODS_APP_*` env vars set.
- [ ] Target repo cloned at the intended commit.
- [ ] `--spend-cap` and `--wall-cap` set appropriately (remember: soft
      ceilings, not hard).

Post-run:

- [ ] `ods explain <run-id>` shows gate Pass.
- [ ] `determinism_ok = true` in the artefact.
- [ ] `rerun-N` report shows overlapping CIs.
- [ ] If a PR was opened, its CI is green.
- [ ] `ods recipes list` shows any harvested candidates; review the
      Generalizer output for sanity before running again.
