# optimization-discovery-system

A CI-integrated, agent-driven performance-optimization product that generalizes byroot's ["faster paths"](https://byroot.github.io/ruby/performance/2026/04/18/faster-paths.html) methodology across languages. Ships as a single static binary (`ods`) built against musl for portability.

## What it does

Given an open-source repository, `ods` runs a typed loop of specialist coding agents to discover, implement, and land perf optimizations without breaking compatibility. Every PR is backed by data (benchmark CIs, syscall/alloc deltas, flame-graph excerpts, compat evidence) — not vibes.

The loop is a direct generalisation of the Ruby blog post's methodology:

```
TargetSelect → Profile → RecipeRetrieve → Hypothesize → Transform →
Verify → Bench → Explain → Harvest
```

Successful transformations are harvested into a reusable **recipe corpus** so the next run converges on known wins without re-paying the reasoning cost.

## Optimization categories (one specialist agent per category)

Mirrors the distinct transforms visible across the blog post, plus one cross-dependency role:

| Specialist              | What it does                                                                    |
|-------------------------|---------------------------------------------------------------------------------|
| `SyscallEliminator`     | Removes redundant syscalls (e.g. `stat` when `readdir` `d_type` suffices)      |
| `AllocReducer`          | Cuts intermediate `Vec`/`String`/variadic allocations                           |
| `FastPathSpecializer`   | Adds a fast path for the common case (ASCII, small-N), preserves slow path     |
| `AlgorithmicFixer`      | Fixes backward-vs-forward scans, early exit, O(n²) → O(n)                      |
| `ValidationRemover`     | Drops validation unreachable under the caller's invariants                     |
| `CachingSpecialist`     | Introduces memoisation / hoists loop-invariant work                             |
| `DependencyOptimizer`   | Proposes dep bumps/swaps where the upstream release has the win                |

## Install

Pre-built static binaries (musl, macOS, Windows) land on GitHub Releases via `.github/workflows/release.yml`.

From source:

```sh
cargo install --path crates/ods-cli
# or for a reproducible musl build:
cargo zigbuild --release --target x86_64-unknown-linux-musl --bin ods
```

## CLI

```
ods scan     <repo>                              # discover hot-primitive candidates
ods run      <repo> --target <lang::mod::sym>    # execute the full loop
ods bench    <repo> --target <lang::mod::sym>    # measurement only
ods verify   <repo> --patch <path>               # compat gate on an existing patch
ods recipes  {list|show|import|export|promote}   # corpus management
ods ci       action <repo>                       # GitHub Actions one-shot mode
ods ci       serve  --port 8787                  # GitHub App webhook server
ods explain  <run-id>                            # regenerate the data-backed report
```

### Run modes

- **dev:** unbounded wall + spend, intended for local research.
- **ci:**  hard caps on both; the run ends gracefully and emits a partial-result report instead of a PR if the cap is exceeded. Example: `ods run . --target rust::std::fs::read_dir --mode ci --wall-cap-s 600 --spend-cap-usd 3.00`.

## Architecture

```
crates/
  ods-cli/        single binary entry (subcommand router)
  ods-core/       domain types + the LoopStage state machine
  ods-agents/     Anthropic tool-use loop, planner, 7 specialists
  ods-measure/    profiler + Criterion-style bootstrap CI stats + env fingerprint
  ods-verify/     zero-diff compat gate, semver + downstream tests
  ods-recipes/    corpus schema + SQLite/vec retrieval + promotion pipeline
  ods-lang/       LanguageAdapter trait + registry
  ods-lang-rust/  Rust adapter (MVP: Cargo / Criterion / cargo-fuzz / tree-sitter)
  ods-ci/         GitHub Actions one-shot + GitHub App webhook server
  ods-report/     PR body renderer (numbers, deltas, evidence, repro cmd)
recipes/seed/     hand-authored starter recipes
```

## The recipe corpus

Embedded SQLite (via `rusqlite` bundled). Vector search is wired through `sqlite-vec` in stage 1 so the binary stays single-binary. Promotion lifecycle:

```
seed  →  candidate  →  validated  →  corpus
```

Seeds are hand-authored YAML under `recipes/seed/`. Candidates are auto-harvested from successful runs. Validated recipes have landed on ≥3 independent repos with zero rollbacks. Corpus-promoted recipes ship as defaults.

## Why Rust, musl, single-binary

- **Portability.** One static binary deploys into any Linux runner (GitHub-hosted, self-hosted, ephemeral containers) without a language runtime or dynamic deps.
- **Agent transport.** We use the Anthropic Messages API directly over `reqwest + rustls` rather than shelling out to a CLI or importing a Python SDK — that would re-introduce runtime-level dependencies and break the musl story.
- **Storage.** Embedded SQLite (`rusqlite` bundled) keeps the corpus in-process; `sqlite-vec` gives us vector search without a separate service.

## Stages of delivery

- **Stage 0 (this commit):** workspace scaffolding, typed LoopStage, CLI surface, recipe schema + store, Rust adapter trait, 2 seed recipes, release workflow.
- **Stage 1:** real Rust adapter (Cargo/Criterion/cargo-fuzz wiring), real profiler (perf_event_open + eBPF), tool-use loop executing on a live target, Actions one-shot PR open.
- **Stage 2:** remaining 5 specialists, recipe retrieval online, promotion pipeline, GitHub App mode with repo allowlist.
- **Stage 3:** `DependencyOptimizer` with cargo-semver-checks + downstream tests; Go adapter.
- **Stage 4:** Ruby (replays the blog post natively as validation), Python, C/C++, JS, Java.

## Status

Stage 0 — scaffolding. The binary builds and the CLI surface is wired end-to-end; real stage execution lands in stage 1.
