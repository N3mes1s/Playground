# optimization-discovery-system docs

`ods` is a CI-integrated, agent-driven performance-optimisation product. It
generalises the methodology in byroot's ["faster paths"](https://byroot.github.io/ruby/performance/2026/04/18/faster-paths.html)
blog post into a reusable system: specialist coding agents discover, verify,
and land perf wins across open-source projects, backed by data (benchmark
CIs, syscall/alloc deltas, flame-graph excerpts, compatibility evidence) —
not by vibes.

Successful transformations are harvested into a reusable **optimization
recipe** corpus so future runs converge on known wins without re-paying the
reasoning cost. Failed retrievals accumulate **negative history** so the
corpus self-curates over time.

## Documentation map

| file | covers |
|---|---|
| [architecture.md](./architecture.md) | The Loop state machine, crate graph, data flow, module responsibilities. |
| [cli.md](./cli.md) | Every `ods` subcommand with concrete examples. |
| [recipes.md](./recipes.md) | Recipe schema, six-state lifecycle, retrieval, anti-pattern library. |
| [agents.md](./agents.md) | Seven specialist roles + Explorer, the tool-use loop, race semantics, harvest + generalizer. |
| [measurement.md](./measurement.md) | Profiler, Criterion ingestion, rerun-N determinism gate, env fingerprint, bench scaffolder. |
| [integrations.md](./integrations.md) | GitHub REST client + App JWT auth + webhook signature verification, Anthropic structured outputs. |
| [operations.md](./operations.md) | Running ods in CI, observability (`ods explain --timeline`), dogfood log. |
| [contributing.md](./contributing.md) | Adding a recipe, language adapter, or specialist. |

## Quick start

### Install

```sh
# From source (within the workspace directory):
cargo install --path crates/ods-cli

# Or for a reproducible musl-static build:
cargo zigbuild --release --target x86_64-unknown-linux-musl --bin ods
```

Dependencies stay musl-clean: `rustls` (not OpenSSL), `rusqlite` bundled,
pure-Rust `rsa` + `pkcs1`/`pkcs8` for GitHub App JWT signing, no `ring`
unless pulled transitively by reqwest.

### Seed the corpus

```sh
ods --store .ods/recipes.db recipes import-dir recipes/seed
ods --store .ods/recipes.db recipes import-dir recipes/antipatterns
ods --store .ods/recipes.db recipes list --all   # 25 Seed + 26 AntiPattern
```

### Point it at a repo

```sh
export ANTHROPIC_API_KEY=...            # only needed when --llm is passed

# Enumerate candidate targets:
ods discover path/to/repo --top 10

# Run the full loop on a single target (measurement-only without --llm):
ods run path/to/repo --target rust::my_crate::my_mod::hot_fn

# With the LLM-driven specialist race:
ods run path/to/repo --target rust::my_crate::my_mod::hot_fn --llm

# Or: fully autonomous — discover, pick top-K, run each under one budget:
ods optimize path/to/repo --budget-usd 20 --top 3 --llm

# Grow the corpus with read-only exploration:
ods explore path/to/repo --budget-usd 5 --max-recipes 10
```

### Read the results

```sh
# The JSON run artifact and a SQLite log land under <repo>/.ods/:
cat path/to/repo/.ods/runs/<run_id>.json

# Full per-agent event timeline (every tool call, every reasoning block):
ods explain path/to/repo <run_id> --timeline
```

## Design principles

The product leans on a few non-negotiable design decisions. They show up
everywhere in the code, so understanding them first makes the rest of the
docs easier to read.

### 1. Data-backed, not vibes.

Every proposed change must pass a statistical speedup check
(`post.ci_lower > pre.ci_upper` at 99% CI, bootstrap-CI sampled ≥30 times)
*and* a zero-diff compatibility gate (existing tests + property/differential
tests + fuzz minutes + semver-check + downstream-consumer tests when it's a
dependency bump). A PR body is only produced when both gates pass. Failed
runs persist NegativeRecords onto the retrieved recipes so the corpus
learns from misses, not just hits.

### 2. The corpus grows itself.

Successful transforms auto-harvest a specific recipe (with repo/commit
provenance) *and* a generalised sibling (via a second LLM turn that
abstracts the pattern away from the specific repo). Retrievals that
abstain or fail leave counter-evidence. A six-state promotion ladder —
`Hypothesized → Seed → Candidate → Validated → Corpus`, plus `AntiPattern`
for target-surfacing-only records — is driven automatically from that
evidence.

### 3. Single static binary, musl-first.

The product ships as one `ods` binary cross-compiled via `cargo-zigbuild`
to `{x86_64,aarch64}-unknown-linux-musl` + the macOS triples. No Python,
no JVM, no OpenSSL dynamic dep. Every integration — Anthropic API, GitHub
REST, recipe storage — runs against embedded libraries so the binary
drops into any CI runner without a language runtime.

### 4. The agent is the last lever, not the first.

Before any LLM call:
1. Lexical + vector retrieval against the recipe corpus.
2. Regex triggers from anti-pattern YAMLs scanning for obvious smells.
3. Fan-in counting to rank candidate targets.

Only when those have picked a target AND selected recipes worth trying
does the Race stage spawn specialists with real API spend. Budget caps
(`wall_cap_s`, `spend_cap_usd`) are enforced at every stage transition.

### 5. Principled abstain beats forced patches.

Specialists are prompted explicitly: *"if the hypothesis does not apply,
end the turn with no diff block — the race will treat it as a principled
abstain."* One live tokei dogfood saw 8/8 specialists abstain on a CLI
module that genuinely had nothing to optimise, at a total cost of $6.65,
and every retrieved recipe accumulated a `NegativeRecord` for that target
— exactly the intended behaviour.

### 6. Anthropic structured outputs, not prompt-and-hope.

The Explorer and any other agent that must produce schema-shaped JSON
uses `output_config.format.json_schema.schema` so token generation is
grammar-constrained. Prose or trailing commas are *impossible* from the
model side. The system prompt handles *behaviour* (what to explore);
the schema handles *format* (what the response must look like).

## Current state (as of this commit)

- **15 workspace crates** (see [architecture.md](./architecture.md)).
- **51 recipes** shipped in `recipes/` (25 Seed, 26 AntiPattern) across
  Rust / Go / Python, covering allocation, hashing, caching, data layout,
  syscalls, SIMD, branch prediction, cache-aware, async, I/O, numeric,
  enum layout, and compile-time pre-computation.
- **7 language adapters** (Rust / Go / Ruby / Python / C/C++ / JS/TS /
  Java). Only the Rust adapter has a fully-wired profiler + scaffolder +
  criterion-JSON ingestion today; others are measurement-capable stubs.
- **86 unit tests** across the workspace, plus one end-to-end integration
  smoke test.
- **10+ successful live dogfood runs** against tokei,
  claude-teleport-analyzer, and the workspace itself. See
  [operations.md](./operations.md) for the log.

## Honest gaps

- `ast_query` is regex-over-lines today. A `tree-sitter` backend slots in
  behind `LanguageAdapter::ast_query` with no caller changes.
- `sqlite-vec` is not wired; vector search uses a hash-based 128-dim
  embedding in pure Rust. Swap-ready.
- Discoverer uses file-stem as the target symbol (not a specific function)
  in autonomous mode; this means `ods optimize` sometimes spends specialist
  budget on whole files that turn out to have nothing hot.
- The Explorer's judgment varies across runs — three live runs against
  tokei produced 1, 1, and 0 recipes respectively. Schema compliance is
  guaranteed; content selection is still at the mercy of the model.

## Licence

Apache-2.0 + MIT.
