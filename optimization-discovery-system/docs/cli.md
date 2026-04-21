# CLI reference

The `ods` binary routes every subcommand through
`crates/ods-cli/src/main.rs`. This reference is grouped by the workflow
stage you're in.

Global flags:

- `--store <path>` — SQLite file for the recipe corpus. Default:
  `./.ods/recipes.db`. Also readable from `ODS_STORE` env var.

Global env vars:

- `ANTHROPIC_API_KEY` — required for any command that spawns
  specialists / Explorer / Generalizer (`run --llm`, `optimize`,
  `explore`, `ci action`).
- `GITHUB_TOKEN` or `ODS_GITHUB_TOKEN` — PAT used by `ci action` to open PRs.
- `ODS_APP_ID`, `ODS_APP_PRIVATE_KEY_PEM`, `ODS_APP_INSTALLATION_ID` —
  alternative to GITHUB_TOKEN; triggers GitHub App JWT auth.
- `ODS_WEBHOOK_SECRET` — HMAC-SHA256 secret for `ci serve`.
- `ODS_ALLOWLIST` — comma-separated `owner/repo` allowlist for server
  mode.
- `ODS_INPUT_PRICE_PER_MTOK`, `ODS_OUTPUT_PRICE_PER_MTOK` — override the
  default Opus pricing when accounting LLM spend.

## Inspect a repo

### `ods scan <repo> [--json]`

Fast file-system sniff: which language adapter matches, + any existing
bench harnesses (Criterion `bench_function`, libtest `#[bench]`, Go
`BenchmarkXxx`). No recipes involved. No LLM calls.

```sh
$ ods scan path/to/my-crate
repo:      path/to/my-crate
language:  rust
candidates (3 found):
  score  language   module::symbol
   1.00  rust       benches::bench_foo::bench_decode      [benches/decode_bench.rs:12]
   1.00  rust       benches::bench_foo::bench_encode      [benches/decode_bench.rs:24]
   0.80  rust       benches::bench_baz::bench_roundtrip   [benches/baz.rs:5]
```

### `ods discover <repo> [--top N] [--json] [--language rust]`

Runs the real autonomous discoverer
(`ods-agents/src/discover.rs::Discoverer::scan_with_recipes`):

1. Enumerates bench candidates like `scan`.
2. Compiles every recipe's `trigger.ast_pattern` as a regex and matches
   each source file.
3. Compiles every anti-pattern's trigger and matches each source file.
4. Counts fan-in via `rg -c <symbol>\(` across `src/`.
5. Scores each candidate:
   `Σ retrieval_score(recipe, 5) × min(5, hits)
    + 0.5 × min(5, anti_pattern_hits)
    + 0.3 × log(fan_in + 1)`

```sh
$ ods --store /tmp/ods.db discover path/to/tokei --top 5
score  target                                         signals
 3.50  rust::cli::cli              recipes:[rust-smallvec-hot-small-collection] anti:[ap-rust-to-string-on-str] fan-in:0
 3.00  rust::language::syntax::syntax           recipes:[rust-smallvec-hot-small-collection] fan-in:0
 1.50  rust::language::language_type::language_type recipes:[rust-smallvec-hot-small-collection] fan-in:0
```

Output is JSON-compatible with `--json`.

## Run the loop

### `ods run <repo> --target <lang::mod::sym> [flags]`

Execute the full nine-stage Loop on a single target.

Flags:

- `--mode {dev|ci}` (default: `dev`). In `ci`, `--wall-cap-s` (default
  900) and `--spend-cap-usd` (default 5.0) are enforced at every stage
  boundary.
- `--llm` — allow the Race stage to spawn specialist conversations.
  Without this flag, the Orchestrator runs the measurement-only pipeline
  (build + profile + tests + bench) and never touches the network for
  LLM calls. Still useful as a baseline check.
- `--wall-cap-s <N>`, `--spend-cap-usd <N>` — only meaningful with
  `--mode ci`.

Target format is `<language>::<module-path>::<symbol>`, where
`<language>` matches an adapter name (`rust`, `go`, etc.). `module-path`
is a colon-separated path the adapter interprets; for Rust it's the
crate-relative module path.

```sh
$ ods run path/to/repo --target rust::my_crate::parser::parse --llm
run 63208fd5-f695-41dd-baee-84d2e9cc21c4 completed
artifact: path/to/repo/.ods/runs/63208fd5-f695-41dd-baee-84d2e9cc21c4.json
zero-diff gate: Pass
winner: FastPathSpecializer (3.86x, lower 3.86x, accepted: true)
```

On `winner: none`:

- Either every retrieved recipe's specialist abstained (saw the code,
  judged the hypothesis didn't fit), or
- One or more specialists applied a patch but the zero-diff gate rejected
  it, or
- No speedup_lower > 1.0 could be established.

Every retrieved recipe picks up a `NegativeRecord` in either case.

### `ods optimize <repo> [--budget-usd N] [--top K] [--mode] [--llm]`

Fully autonomous:

1. `Discoverer::scan_with_recipes(repo, store, top=K)` picks targets.
2. For each candidate, `Orchestrator::run(target, allow_llm)` executes.
3. Stops early when accumulated spend ≥ `--budget-usd`.
4. Writes `<repo>/.ods/batches/<batch_id>.json` referencing all child run
   ids, total spend, winner count.

```sh
$ ods --store /tmp/ods.db optimize path/to/tokei --budget-usd 10 --top 3 --llm
batch 2942a47f-203c-4bc7-aeab-0d6182941e92 done: 1 runs, total spend $6.65, winners 0
```

Note: the budget is per-batch, not per-target. One specialist-heavy
target can exhaust the whole budget before other candidates are tried.

### `ods explore <repo> [--budget-usd N] [--max-recipes N] [--language rust] [--dry-run]`

Read-only corpus growth. Runs the Explorer specialist (system prompt
mandates `list_dir` + `read_file` ×≥3 + `ast_query` ×≥2 +
`recipe_search`) and upserts its proposed recipes as `Hypothesized`.

Grammar-constrained via Anthropic's `output_config.format.json_schema`,
so the final text is always parseable JSON matching our Recipe
envelope schema. See [integrations.md](./integrations.md#structured-outputs).

```sh
$ ods --store /tmp/ods.db explore path/to/tokei --budget-usd 3 --max-recipes 5
explorer: 1 proposed recipes (cost $1.98, iters 9, tok_in 121485, tok_out 2121)
  hot-starts-with-table [fast-path-specialization] Lift and pre-byte-ify hot start pattern lists
upserted 1 new Hypothesized recipes
```

`--dry-run` prints proposed recipes without upserting — good for
previewing before polluting the corpus.

### `ods bench <repo> --target <sig>`

Measurement-only: build, run the target's bench, print the parsed
`BenchReport` as JSON. No patches, no tests, no LLM. Useful for
verifying the adapter parses your project's bench output correctly.

### `ods verify <repo> --patch <path>`

Apply `<path>` to a copy-on-write worktree of the repo, run the language
adapter's build + tests + fuzz (1 minute) on the patched state, evaluate
the `ZeroDiffGate`. Prints the `GateReport` as JSON. No LLM.

Used to re-verify a specific diff — for example, a patch the operator
hand-applies from a prior `run` artifact.

## Manage the corpus

### `ods recipes list [--language L] [--all]`

Lists recipes at promotion ≥ `Seed` by default. `--all` includes
`Hypothesized` and `AntiPattern`. `--language` filters.

```sh
$ ods --store /tmp/ods.db recipes list --all | head
rust-readdir-dtype                                   rust     Seed          syscall-elimination       avoid stat(2) when readdir d_type already classifies the entry
rust-smallvec-hot-small-collection                   rust     Seed          alloc-reduction           replace hot-path Vec with SmallVec when typical length is small
...
ap-rust-loop-vec-alloc                               rust     AntiPattern   alloc-reduction           Vec::new() allocated inside a loop
```

### `ods recipes show <id>`

Prints the full YAML for one recipe, including `success_history`,
`negative_history`, and links (`generalized_from` / `generalized_as` /
`source_patch_ref`). Useful for audit.

### `ods recipes search <query> [--language L] [--limit N]`

BM25-ranked lexical search. Different from vector retrieval used by
the Planner: this is for humans browsing the corpus.

```sh
$ ods --store /tmp/ods.db recipes search "readdir stat syscall" --limit 3
 2.881  rust-readdir-dtype                  [syscall-elimination]   avoid stat(2) when readdir d_type already classifies the entry
 1.187  ap-rust-metadata-is-dir             [syscall-elimination]   .metadata() to ask only is_dir / is_file
 0.000  rust-path-join-fastpath             [fast-path-specialization]  fast path for ASCII-clean PathBuf::push and PathBuf::join
```

### `ods recipes import <path.yaml>`

Upsert one recipe from a YAML file. The embedding is auto-populated.

### `ods recipes import-dir <path>`

Walk a directory, upsert every `*.yaml`. Skips duplicates, reports a
count. Used to seed a fresh store:

```sh
ods --store .ods/recipes.db recipes import-dir recipes/seed
ods --store .ods/recipes.db recipes import-dir recipes/antipatterns
```

### `ods recipes export <out.yaml>`

Dumps every recipe in the store to a single YAML stream.

### `ods recipes promote <id> --to {seed|candidate|validated|corpus}`

Manually set the promotion state. Use sparingly — the normal path is
automatic promotion via `Recipe::success_history`.

## Explain prior runs

### `ods explain <repo> <run_id>`

Prints the JSON artifact at `<repo>/.ods/runs/<run_id>.json`. Includes
pre/post profiles, speedup verdict, gate report, recipes applied, patch
diff if any.

### `ods explain <repo> <run_id> --timeline`

Reads the `run_events` table in `<repo>/.ods/runs.db` and prints every
emitted `AgentEvent` in order: `race-start`, `specialist-start`, `turn`
(with token counts), `reasoning` (preview), `tool-call` (tool + input
preview), `tool-result` (ok flag + output preview), `patch-proposed`,
`patch-rejected`, `specialist-finish`, `race-finish`, stage `done`
markers.

```
[2026-04-19T12:09:42Z]    5 transform              reasoning        SyscallEliminator iter=6 >> The hypothesis mentions readdir/d_type, but score_recipes is actually BM25 text scoring...
[2026-04-19T12:09:42Z]    6 transform              tool-call        SyscallEliminator iter=6 ast_query({"path":"crates/ods-recipes/src/score.rs","pattern":"metadata|file_type"})
```

Replay is deterministic — no re-execution, just reads SQLite rows.
Useful for PR review ("show me everything the agent did") without
re-burning API dollars.

## GitHub integration

### `ods ci action <repo> --target <sig> --github-repo <owner/name> [flags]`

One-shot GitHub Actions mode:

1. Run the full Loop on `<repo>` targeting `<sig>`.
2. Create branch `<--branch-prefix>/<run_id>` (default `ods/optimize`)
   off the repo's default branch.
3. Commit the run artifact to `docs/ods/runs/<run_id>.json` on that
   branch via the GitHub Contents API.
4. Open a PR with body rendered by `ods-report::render_pr_body` —
   speedup headline, CI bounds, syscall/alloc deltas, recipes applied
   (with their `success_history` and `negative_history` counts), compat
   evidence, reproduction command. See [integrations.md](./integrations.md#pr-body-format).

Auth:

- Default: `GITHUB_TOKEN` or `ODS_GITHUB_TOKEN`.
- GitHub App: set all three of `ODS_APP_ID`,
  `ODS_APP_PRIVATE_KEY_PEM`, `ODS_APP_INSTALLATION_ID`. Triggers RS256
  JWT signing (pure-Rust `rsa` + `pkcs1`/`pkcs8`) and installation-token
  exchange.

`--allowlist owner/a,owner/b,...` (also readable from `ODS_ALLOWLIST`)
gates which repos we're allowed to post PRs against.

### `ods ci serve [--port 8787]`

Long-running webhook server (axum, `ods-ci/src/webhook.rs`):

1. Validates `X-Hub-Signature-256` against `ODS_WEBHOOK_SECRET` in
   constant time (HMAC-SHA256, `ods-ci/src/signature.rs`).
2. Parses `issue_comment.created` payloads.
3. Accepts `/ods optimize <target>` comment commands from allowlisted
   users.
4. Forwards parsed events on an `mpsc::UnboundedReceiver<WebhookEvent>`
   to the caller (today: logs; tomorrow: triggers a run).

Endpoints:

- `GET /health` — 200 "ok".
- `POST /webhook` — GitHub event sink.
