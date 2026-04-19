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
  ods-cli/          single binary entry (subcommand router)
  ods-core/         domain types + LoopStage state machine + git-worktree helpers
  ods-exec/         subprocess primitive with timeout + structured capture
  ods-agents/       Anthropic tool-use loop, orchestrator, planner, 7 specialists, typed toolkit
  ods-measure/      profiler + Criterion-style bootstrap CI stats + env fingerprint
  ods-verify/       zero-diff compat gate, cargo-semver-checks + downstream runner
  ods-recipes/      corpus schema + SQLite store + BM25 scoring + auto-promotion
  ods-lang/         LanguageAdapter trait + registry
  ods-lang-rust/    Rust adapter (cargo build/test/bench/fuzz + perf/strace profiler)
  ods-lang-go/      Go adapter (go test, go test -bench, go test -fuzz)
  ods-lang-ruby/    Ruby adapter (bundle + minitest/rspec + benchmark-ips)
  ods-lang-python/  Python adapter (pytest + pytest-benchmark)
  ods-lang-c/       C/C++ adapter (cmake/make + ctest + google-benchmark)
  ods-lang-js/      JS/TS adapter (npm test + jest/vitest/tinybench)
  ods-lang-java/    Java adapter (mvn/gradle + surefire/JMH)
  ods-ci/           GitHub REST API client + Actions one-shot + App webhook server
  ods-report/       PR body renderer (numbers, deltas, evidence, repro cmd)
recipes/seed/       hand-authored starter recipes
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

- **Stage 0 ✅** workspace scaffolding, typed LoopStage, CLI surface, recipe schema + store, Rust adapter trait, 2 seed recipes, release workflow.
- **Stage 1 ✅** real Rust adapter over subprocess (`cargo build/test/bench/fuzz`), profiler wrapping `/usr/bin/time` + `strace -c` + `perf stat`, typed Anthropic tool-use loop with conversation runner + token accounting + prompt-cache aware stats, typed specialist toolkit (`read_file`, `list_dir`, `ast_query`, `apply_patch`, `run_tests`, `run_bench`) behind a path-sandbox gate, git-worktree helper, orchestrator walking `TargetSelect → … → Harvest` with JSON artifact persistence, GitHub REST client + `ods ci action` opening PRs.
- **Stage 2 ✅** BM25 recipe retrieval (`ods recipes search`), auto-promotion rules (seed → candidate → validated → corpus) driven by success history, axum webhook server accepting `/ods optimize` comments with an `owner/repo` allowlist.
- **Stage 3 ✅** `cargo-semver-checks` subprocess wrapper with breaking-change parser, downstream-consumer test runner for dep bumps (cargo/go/npm/pytest auto-pick), Go adapter (`go test`, `go test -bench`, `go test -fuzz`).
- **Stage 4 ✅** Ruby, Python, C/C++, JS/TS, Java adapters (detect + build + test + bench output parsers for minitest / rspec / pytest / pytest-benchmark / ctest / jest / vitest / tinybench / mvn surefire / gradle / benchmark-ips).

## Status

Stages 0–4 wired end-to-end. What's real vs. stubbed:

- **Real:** the Loop state machine + autonomy budget gate, orchestrator persistence to `.ods/runs/<run_id>.json`, recipe store + BM25 ranking + promotion, seven language adapters driving real toolchains through `ods-exec`, Linux profiler via `/usr/bin/time` + `strace -c` + `perf stat`, tool-use loop with dispatch + token accounting, GitHub REST client (branch create, file commit via Contents API, PR open), webhook server with comment allowlist, `cargo-semver-checks` + downstream-consumer gate wiring in the zero-diff verifier.
- **Stubbed / seams only (for follow-on work):**
  - AST queries use regex over lines today; a tree-sitter backend can slot in behind `LanguageAdapter::ast_query` with no caller changes.
  - The LLM transform step exists (ToolUseLoop.run + specialist prompts + toolkit) but the orchestrator does not autonomously invoke it yet. Add `--llm` handling in the orchestrator to race specialists in worktrees.
  - Webhook signature verification (`X-Hub-Signature-256`) is TODO.
  - Criterion JSON ingestion is regex-based against stdout; a `--bench-json` path lands next.

## CLI reference

```
ods scan     <repo> [--json]
ods run      <repo> --target <lang::mod::sym> [--mode dev|ci] [--wall-cap-s N] [--spend-cap-usd N] [--llm]
ods bench    <repo> --target <lang::mod::sym>
ods verify   <repo> --patch <path>
ods recipes  list   [--language <lang>]
ods recipes  show   <id>
ods recipes  search <query> [--language <lang>] [--limit N]
ods recipes  import <path.yaml>
ods recipes  export <out.yaml>
ods recipes  promote <id> --to seed|candidate|validated|corpus
ods ci       action <repo> --target <sig> --github-repo <owner/name> [--base <branch>] [--allowlist owner/a,owner/b]
ods ci       serve  [--port 8787]
ods explain  <repo> <run-id>
```
