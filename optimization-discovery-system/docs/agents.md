# Agents — specialists, Explorer, and the tool-use loop

Every LLM call the product makes goes through one piece of
infrastructure: the `ToolUseLoop` in `crates/ods-agents/src/anthropic.rs`.
Seven specialists + one Explorer + one Generalizer are all built on top
of it, each with a different system prompt and toolkit allowlist.

## `ToolUseLoop`

```rust
pub struct ToolUseLoop {
    pub max_iters: u32,
    pub max_tokens: u32,
    pub tool_specs: Vec<ToolSpec>,
    pub output_schema: Option<serde_json::Value>,  // structured outputs
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}
```

`run_observed(client, system, initial_user_msg, observer)` is the main
entry point. It sends a message to Claude, inspects the response:

- If there are `tool_use` blocks, dispatch each via `handlers`, append
  `tool_result` blocks to the conversation, go around again.
- If the stop reason is `end_turn` with no tool_use, return the final
  text + token stats + conversation history.

The `observer` is a `ConversationObserver<'_>` of four callbacks
(`on_turn`, `on_reasoning`, `on_tool_call`, `on_tool_result`). Every
`AgentEvent` emitted during a race flows through that interface, so
`ods explain --timeline` can replay everything later without
re-execution.

Token usage is tallied into `LoopStats` (input, output, cache-read,
cache-creation) and `estimated_cost_usd()` converts to dollars using
per-million-token prices read from env vars (Opus defaults). This is
what the race sums into `RaceOutput.spent_usd` for budget enforcement.

`output_schema: Option<Value>` is forwarded to
`send_messages_with_schema(..., schema)`, which attaches
`output_config.format.json_schema.schema` to the request body. See
[integrations.md](./integrations.md#structured-outputs) for the wire
format and [the Anthropic docs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).

## Toolkits

Tools are typed Rust functions registered into a
`ToolUseLoop`. `crates/ods-agents/src/tools.rs::ToolHandlerMap` provides
two registration bundles:

### `register_read_only(&mut loop_, Sandbox::new(repo_path))`

- `read_file` — read a UTF-8 text file relative to the sandbox.
- `list_dir` — list dir entries (`f filename` or `d dirname`).
- `ast_query` — regex over lines, returns `path:line: matching line`.
  (Tree-sitter backend will slot in here.)

All three validate paths through `Sandbox::resolve`, which uses a
lexical normaliser that rejects `..` traversal *without* relying on
filesystem state (so it works on not-yet-existent paths too).

### `register_mutating(&mut loop_, Sandbox::new(repo_path))`

Everything above, plus:

- `apply_patch` — writes the diff to a tempfile, calls `git apply` if
  `.git` is present, else `patch -p1`. Returns "applied" or the tool's
  stderr on failure.
- `run_tests` — dispatches to the language-appropriate command
  (`cargo test --workspace --no-fail-fast --quiet`, `go test ./...`,
  `pytest -q`, `npm test`, `ctest --output-on-failure`, etc.). Returns
  `status + stdout + stderr`, truncated.
- `run_bench` — `cargo bench --workspace -- <filter>` for Rust (the
  other adapters' bench wiring is thinner).

The Explorer never gets the mutating toolkit, by design. The race's
specialists get both.

## Planner

`crates/ods-agents/src/planner.rs::Planner::plan(target,
observed_categories)`:

1. Build a free-form query string from `target.language`,
   `target.module`, `target.symbol`, and every observed category name.
2. Call `store.retrieve(Some(&language), &query, 8)`.
3. Emit one `(SpecialistKind, Hypothesis)` pair per retrieved recipe,
   routed to the specialist matching the recipe's category.
4. If retrieval returned nothing, cold-start: one hypothesis per
   `OptimizationCategory` with `seed_recipe_id: None` — all seven
   specialists get a turn so downstream can race in parallel.

## Specialists

Seven specialists, defined in
`crates/ods-agents/src/specialist.rs::SpecialistKind`:

| kind | category | summary prompt |
|---|---|---|
| `SyscallEliminator` | syscall-elimination | "Eliminate redundant syscalls. Preferred moves: use d_type from readdir entries, cache stat results, batch file metadata lookups." |
| `AllocReducer` | alloc-reduction | "Reduce allocations. Preferred moves: prefer borrowed slices, SmallVec for small-N, replace variadic collection with explicit argc/argv." |
| `FastPathSpecializer` | fast-path-specialization | "Add a fast path for the common case while preserving a correct slow path. Typical: ASCII vs general, single- vs many-argument, zero-length inputs." |
| `AlgorithmicFixer` | algorithmic | "Fix algorithmic inefficiencies: backward scans where appropriate, early exit, O(n²) → O(n)." |
| `ValidationRemover` | validation-removal | "Remove validation that is unreachable given the caller's invariants. You must prove the invariant holds from callers before removing the check." |
| `CachingSpecialist` | caching | "Introduce memoisation or hoist loop-invariant work. Caching must be referentially transparent." |
| `DependencyOptimizer` | dependency-optimization | "Propose dependency bumps or swaps where the upstream release contains the optimisation. Verify cargo-semver-checks + downstream builds." |

Each also inherits a standard operator prompt that enforces:

1. Use `read_file` / `list_dir` / `ast_query` to explore.
2. If a scaffolded bench exists with a `black_box(())` placeholder, rewrite
   the `b.iter(...)` body to exercise the target — otherwise pre/post is
   noise.
3. Produce a minimal unified-diff patch that implements the hypothesis.
4. Call `apply_patch`, then `run_tests` to verify semantics.
5. Call `run_bench` to confirm a measurable improvement.
6. **If you conclude the hypothesis doesn't apply, end with NO diff
   block — the race will treat it as a principled abstain rather than
   a forced bad patch.**
7. When patching, include the final unified diff verbatim in a
   ```diff fenced block so the race can extract it.

Guideline #6 is load-bearing. Without it specialists would force
plausible-looking patches that fail the gate, burning API dollars on
doomed attempts. See [operations.md](./operations.md#tokei-2025-04-19)
for the dogfood that confirmed it's working.

## Race

`crates/ods-agents/src/race.rs::run_specialists(RaceInput)` is what
happens inside the `Transform` stage when `--llm` is passed.

Shape:

```rust
pub struct RaceInput<'a> {
    pub repo: &'a Path,
    pub target: &'a TargetSig,
    pub adapter: Arc<dyn LanguageAdapter>,
    pub plan: Vec<(SpecialistKind, Hypothesis)>,
    pub mode: Mode,
    pub pre_bench: Option<BenchReport>,
    pub recipe_snippets: Vec<String>,
    pub worktree_parent: PathBuf,
    pub fuzz_budget: Duration,
    pub sink: Option<Arc<dyn EventSink>>,
    pub run_id: RunId,
}
```

For each `(kind, hypothesis)` in `plan`:

1. `Worktree::create(repo, tag, worktree_parent)` — tries
   `git worktree add --detach` first; falls back to `copy_dir` (which
   skips `.git`, `target`, `node_modules`, `.ods`, etc.). Returns a
   `WorktreeHandle` whose `Drop` impl cleans up.

2. Build a `ToolUseLoop` with both toolkits registered against a
   `Sandbox::new(wt.path)`.

3. `loop.run_observed(client, specialist.system_prompt(), user_prompt,
   observer)`. Every turn / reasoning block / tool call / tool result is
   emitted as an `AgentEvent` to the sink (SqliteEventSink by default,
   for later `ods explain --timeline`).

4. Extract the last ```diff block from the final text (or abstain if
   none).

5. If we got a diff:
   - `adapter.build(&wt.path, Some(&patch))` — re-build in the worktree.
   - `adapter.run_tests(&build, Full)`.
   - `adapter.fuzz(&build, target, fuzz_budget)` if cargo-fuzz (or
     equivalent) is available.
   - `ZeroDiffGate::evaluate` — pass or reject with reasons.
   - If pass: `adapter.run_bench`, compute `SpeedupVerdict` against
     `pre_bench`. Only when `verdict.accepted` (CI lower > 1) does this
     specialist become a winner candidate.

6. If no diff or any gate fails or no speedup: push a
   `NegativeRecord { outcome: Abstained | RejectedByGate |
   NoMeasuredSpeedup, repo, target_symbol, recorded_at }` keyed on the
   retrieved recipe id (when `hyp.seed_recipe_id.is_some()`). The
   orchestrator later persists these via `harvest::record_negatives`.

7. Drop the worktree.

After the loop, pick the winner by `max_by(speedup_lower)` among
accepted candidates. If no winner, return `RaceOutput { winner: None,
… }`. The orchestrator respects that and does not claim a speedup post-
race. (That post-race speedup-reporting was a real bug in an earlier
stage; see [operations.md](./operations.md#product-bugs-fixed-during-dogfood).)

Budget enforcement: the race checks `spent_usd >= budget.spend_cap_usd`
between specialists in `Mode::Ci`. This means real spend can overshoot
by the cost of the in-flight specialist — documented in
[architecture.md](./architecture.md#mode--budget-enforcement).

## Explorer

`crates/ods-agents/src/explorer.rs::run_explorer(ExplorerInput)` —
read-only corpus growth.

```rust
pub struct ExplorerInput<'a> {
    pub repo: &'a Path,
    pub language: String,
    pub max_recipes: u32,
    pub max_iters: u32,
}
```

Setup:

1. `ToolUseLoop` with ONLY the read-only toolkit
   (`register_read_only`). No `apply_patch`, no `run_tests`, no
   `run_bench`. The Explorer can *survey* but cannot mutate.

2. `output_schema = Some(explorer_output_schema())` — grammar-constrains
   the final text block to a strict
   `{"recipes": [{id, name, category (enum), ast_pattern, profile_signature[],
    steps[], invariants[]}]}` shape, `additionalProperties: false` at
   every level. The model *cannot* emit trailing commas or prose
   outside the schema. See [integrations.md](./integrations.md#structured-outputs).

3. System prompt (`SpecialistKind::Explorer`) is process-oriented:

   > Before emitting your final response you MUST:
   > 1. `list_dir` on repo root AND on the primary source directory.
   > 2. `read_file` on ≥3 files that look hot (parsers, core loops,
   >    formatters, I/O, hashing).
   > 3. ≥2 `ast_query` calls looking for concrete smells.
   > 4. 1 `recipe_search` to avoid proposing duplicates.
   >
   > Only THEN finalise. Returning an empty `{"recipes": []}` on
   > iteration 1 is a failure mode — don't take that shortcut.

4. User prompt lists the JSON shape again and reminds the model that
   patterns must describe a SHAPE (regex trigger + fix), not a one-off
   fix for a specific function.

Output: `ExplorerOutcome { proposed_recipes, spent_usd, tokens_in,
tokens_out, iterations, final_text }`. The `final_text` is kept for
diagnostics so operators can see what the model actually emitted on a
run that returned zero recipes.

Behavior in live dogfood against tokei:

| run | budget | iters | cost | recipes |
|---|---|---|---|---|
| before schema, prompt-only | $5 | 12 | $3.67 | 0 (parser failed) |
| after parser fix, dry | $3 | 4 | $0.81 | 0 (escape hatch) |
| after stricter prompt | $3 | 9 | $1.90 | 0 (parser bug) |
| **after `output_config` wiring** | **$2** | **9** | **$1.98** | **1** (`hot-starts-with-table`) |
| repeat, different seed | $0.10 | 7 | $1.23 | 1 (`precompute-bytes-for-repeated-starts-with`) |
| repeat, non-dry | $2 | 9 | $1.90 | 0 (model declined) |

Variance across runs is model-level, not wiring. The structured-output
wiring guarantees schema compliance; it does not guarantee the model
will always find something worth proposing.

## Harvest + Generalizer

`crates/ods-agents/src/harvest.rs::harvest_full(winner, target, repo,
commit, store, client)` runs in two phases after a race winner:

### Phase 1: narrow recipe (specific + provenance)

Synthesises an id like `auto-rust-fastpath-ods_recipes-score-score_recipes`
(language + kind-slug + module + symbol), populates:

- `promotion: Candidate` (first win auto-promotes from any ladder
  level ≤ Candidate).
- `trigger.ast_pattern = extract_ast_hint(diff)` — first added line of
  the patch.
- `trigger.profile_signature = ["hot:<module>::<symbol>"]`.
- `transformation.steps` = first 10 non-blank lines of the specialist's
  rationale.
- `success_history = [{repo, commit, speedup, ci_lower, merged: false}]`.
- `source_patch_ref = <commit>`.

Merges with any prior recipe of the same id (accumulates
`success_history`, preserves `generalized_as` link). Runs
`promote_on_success`.

### Phase 2: generalised sibling (reusable pattern)

Exactly one extra Anthropic call with the system prompt:

> You are the Generalizer role in the ods product. Given a concrete patch
> that sped up a specific function, you describe the REUSABLE pattern
> (not this one change) in our Recipe JSON schema. The output must
> reference no repo-specific identifiers — no crate name, no module
> name, no function name — it must describe the AST shape of the
> trigger, the profile signature, and the ordered transformation steps
> in pattern-level language.

User prompt includes the target sig, the specialist kind, rationale,
and the patch diff, plus the target JSON schema (id, name, category
enum, language, ast_pattern, profile_signature[], steps[],
invariants[]).

Output: a second `Recipe` with `promotion: Hypothesized` and
`generalized_from: Some(specific_id)`. The specific recipe then gets
`generalized_as: Some(general_id)`.

If this second call fails (network, parse error, unknown category),
Phase 2 is skipped silently — Phase 1 still lands.

Why Hypothesized for the generalised form? Because it's a single-LLM-
turn abstraction from one data point. The next time a race hits an
unrelated repo with the same shape, if the generalised recipe helps,
it picks up a success record and the promotion ladder carries it up to
Candidate → Validated.

## NegativeRecord persistence

`harvest::record_negatives(recipe_ids, repo, target, outcome, store)`:

For each retrieved recipe that failed to help this run:

1. `store.get(&id)?` → `Some(recipe)`.
2. Append a `NegativeRecord { repo, target_symbol, outcome,
   recorded_at }` to `recipe.negative_history`.
3. Cap at 200 entries (rolling window — older ones are drained).
4. `promote_on_negative(&recipe, rules)` — if Hypothesized with ≥3
   distinct-repo negatives and zero successes, returns
   `PromotionOutcome::Retire`. Caller deletes. Otherwise: upsert
   back.

This is what makes the corpus self-curating. Explorer-proposed
Hypothesized recipes that consistently don't fit anywhere retire
themselves within a handful of runs. Seed and higher never auto-retire
— they need a human demotion via `ods recipes promote --to seed` or a
direct SQL update.
