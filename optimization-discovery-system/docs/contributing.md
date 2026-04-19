# Contributing

Three patterns show up over and over:

1. **Adding a recipe** — extend the corpus.
2. **Adding a language adapter** — teach `ods` a new language.
3. **Adding a specialist** — give the Planner a new transformation
   category.

This doc walks through each. All of them are additive; none require
touching the Loop or the gate.

---

## Adding a recipe

Recipes are YAML files under `recipes/<state>/<id>.yaml`. `state` is
usually `seed` (hand-authored, blessed) or `antipatterns` (targets to
surface, never auto-apply). `Candidate`, `Validated`, and `Corpus`
states are reached through the promotion pipeline at runtime and
stored in `runs.db` + exported on demand.

### Minimal template

```yaml
id: rust-smallvec-for-bounded-n           # kebab-case, <lang>-<category>-<shape>
name: prefer SmallVec<[T; N]> when N is bounded and small
category: alloc-reduction                 # see recipes.md for enum
language: rust
promotion: seed

trigger:
  ast_pattern: 'let\s+mut\s+\w+\s*:\s*Vec<.*?>\s*='
  profile_signature:
    - "hot-path:alloc-spike-on-small-collections"
    - "pahole:heap-ptr-for-tiny-collections"
  naive_alt_ratio_min: null               # required speedup vs naive alt; null = no floor

transformation:
  steps:
    - "Identify local Vec<T> whose size is bounded by a compile-time
       constant N <= 32."
    - "Replace the declared type with `SmallVec<[T; N]>` from the
       smallvec crate."
    - "Import smallvec; add `smallvec = { version = \"2\", features = [\"const_new\"] }`
       to Cargo.toml if not present."
    - "Rewrite constructors: `Vec::new()` → `SmallVec::new()`; `vec![...]`
       → `smallvec![...]`."
    - "Invariants: N is a true upper bound; pushing past N transitions to
       heap transparently; method surface stays Vec-compatible for the
       call sites that use it."

verification:
  test_selectors: ["alloc", "collection", "push", "pop"]
  property_seeds: []
  fuzz_minutes: 0
  semver_check: false

benchmark_template: ""
success_history: []
negative_history: []
generalized_from: null
generalized_as: null
source_patch_ref: "hand-authored"
embedding: null                           # auto-populated on upsert
```

### Field guide

| Field                            | Why it matters |
|----------------------------------|----------------|
| `id`                             | Stable key; retrieval, logs, and `success_history` join on this. |
| `category`                       | Routes retrieval to the right specialist(s). |
| `language`                       | First-pass filter in `Store::search`. |
| `trigger.ast_pattern`            | Regex run per source file by `Discoverer::scan`. Anchor carefully — over-broad triggers surface the recipe too often and earn `NegativeRecord` entries. |
| `trigger.profile_signature`      | Free-text signals the Planner blends with the `ast_pattern` match to decide whether to apply. Matches against `ProfileReport.syscall_counts`, flame frames, etc. |
| `transformation.steps`           | Ordered and imperative; one specialist turn should be able to follow them. |
| `verification.test_selectors`    | Names or paths the gate should specifically care about. Hint, not enforcement. |
| `verification.fuzz_minutes`      | Minimum fuzz budget for this transformation; 0 disables. |
| `verification.semver_check`      | Trigger `cargo-semver-checks` when the transformation could touch public API. |
| `promotion`                      | Starting state. Hand-authored recipes should be `seed`; exploration outputs are `hypothesized`. |

### Importing after authoring

```bash
ods recipes import recipes/seed/rust-smallvec-for-bounded-n.yaml
ods recipes list | grep smallvec
```

`import` validates the schema, computes the embedding, and upserts into
`recipes.db`. `import-dir` recurses and imports the whole tree — useful
after adding a batch of recipes.

### Testing a recipe against a real repo

```bash
ods discover /path/to/repo --language rust | grep rust-smallvec-for-bounded-n
ods run     /path/to/repo --target <symbol-from-discover> --dry-run
```

`--dry-run` applies the recipe's steps in a worktree but doesn't run
tests or the race — useful for iterating on the `ast_pattern`.

### Anti-pattern vs recipe

An **anti-pattern** is a recipe with `promotion: antipattern`. It surfaces
as a target in `Discoverer::scan` but is never dispatched to a specialist
for automatic application. Use anti-patterns when you want the
Discoverer's scoring to boost a symbol but a human still needs to pick
the right transform.

---

## Adding a language adapter

`ods` talks to languages through one trait:

```rust
// crates/ods-lang/src/lib.rs
#[async_trait]
pub trait LanguageAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn detect(&self, repo: &Path) -> Result<bool>;
    async fn build(&self, repo: &Path, patch: Option<&Patch>) -> Result<Build>;
    async fn run_tests(&self, build: &Build, scope: TestScope) -> Result<TestReport>;
    async fn run_bench(&self, build: &Build, target: &TargetSig) -> Result<BenchReport>;
    async fn profile(&self, build: &Build, target: &TargetSig) -> Result<ProfileReport>;
    async fn ast_query(&self, file: &Path, query: &str) -> Result<Vec<AstMatch>>;
    fn emit_patch(&self, edits: &[Edit]) -> Result<Patch>;
    async fn fuzz(&self, build: &Build, target: &TargetSig, budget: Duration) -> Result<FuzzReport>;
}
```

### Checklist for a new adapter (e.g. `ods-lang-go`)

1. New crate `crates/ods-lang-go/` with `Cargo.toml` listing
   `ods-core`, `ods-lang`, `ods-exec`, `anyhow`, `async-trait`,
   `regex`, `serde`, `tokio`, `tracing`.
2. `GoAdapter` struct + `LanguageAdapter` impl:
   - `detect`: `go.mod` present.
   - `build`: `go build ./...` (+ optional patch application before).
   - `run_tests`: `go test ./...` → parse per-package JSON
     (`go test -json`) for pass/fail/skip.
   - `run_bench`: `go test -bench=. -benchtime=5s -json` → parse
     `BenchmarkResult.NsPerOp` into `BenchSample`.
   - `profile`: wrap `go test -bench=<sym> -cpuprofile=... -memprofile=...`
     then parse with `go tool pprof -text`.
   - `ast_query`: `go/ast` via a small helper, or regex as a stage-1
     placeholder.
   - `emit_patch`: use the same `similar::TextDiff` unified-diff emitter
     the Rust adapter uses.
   - `fuzz`: `go test -run=X -fuzz=Fuzz<...> -fuzztime=<budget>`.
3. Register the adapter in `ods-lang/src/adapter.rs`'s default
   registry, gated by `cfg(feature = "go")` if you want opt-in
   compilation.
4. Seed at least 3 recipes: one per category that's idiomatic to the
   language. For Go, a good starter trio is "avoid interface boxing in
   hot loops", "prefer bytes.Buffer over string concat", "`sync.Pool`
   for allocation-heavy pipelines".
5. Integration test: construct a fixture project in a tempdir, run
   `Orchestrator::run` end-to-end in dev mode, assert the artefact
   contains non-empty `stages_completed`.

### Bench vs profile, cleanly separated

The `profile` call returns a `ProfileReport` (counters, syscall counts,
flame-graph path). The `run_bench` call returns per-bench ns/iter
samples. These are separate because they serve different gates: the
profile drives *what to change* (hot functions), the bench drives
*whether the change worked* (speedup verdict). Keep your adapter's
implementations correspondingly distinct.

### MVP fuzz is allowed to be a no-op

`fuzz` may legitimately return `FuzzReport { minutes: 0, crashes: 0,
seed_corpus_size: 0 }` on stage-1 adapters. The gate treats absent fuzz
as "soft pass" (noted in the PR body) rather than a hard fail. Ship the
adapter without fuzz if the language ecosystem doesn't have a clean
harness; add it in stage-2.

---

## Adding a specialist

A specialist is an `LLM-backed` optimiser scoped to one
`OptimizationCategory`. The wiring is in `crates/ods-agents/src/`:

```
specialist.rs     # SpecialistKind enum + per-kind system prompt
tools.rs          # Tool schemas + handler map + read-only/mutating subsets
race.rs           # Worktree + ToolUseLoop per kind, winner by speedup_lower
planner.rs        # Recipe-first routing → ranked (kind, hypothesis) pairs
harvest.rs        # Narrow + generalizer harvest on race wins
```

### Checklist for a new specialist (e.g. `PageFaultReducer`)

1. Add the variant to `SpecialistKind`:
   ```rust
   pub enum SpecialistKind {
       ...,
       PageFaultReducer,
   }
   ```
2. Implement `SpecialistKind::category` — return the matching
   `OptimizationCategory`. If there isn't one, first extend
   `OptimizationCategory` in `ods-core`; be thoughtful, the category
   enum is also the recipe retrieval key.
3. Implement `SpecialistKind::system_prompt` — a terse,
   category-specific prompt describing preferred moves, invariants to
   preserve, and what NOT to do. Look at the existing seven for style.
4. Update `harvest::kind_slug` to cover the new variant so harvested
   recipe ids include it (`auto-<lang>-<kind_slug>-<module>-<symbol>`).
5. Update `planner::plan` if the specialist needs custom hypothesis
   shaping beyond the default recipe-first routing.
6. Decide on the tool allowlist:
   - Most specialists get the full mutating toolkit (`apply_patch`,
     `run_tests`, `run_bench`, …).
   - Read-only exploratory specialists (like `Explorer`) get the
     read-only subset. See `tools::register_read_only`.
7. Add at least 2 recipes with the new specialist's category; without
   them the Planner has nothing to route to.

### Why specialists don't have Rust code per-category

The specialisation is in the *system prompt* and the *allowed tools*,
not in per-kind handlers. The `ToolUseLoop` is the same loop for every
specialist; what differs is the prompt, the tool allowlist, and the
recipes retrieved as prior context. This keeps the surface area small
and makes adding specialists a YAML-and-prompt change rather than a
code-and-plumbing change.

### When to add a specialist vs a recipe

- Add a **recipe** when the transformation is mechanical and shape-based
  (regex + rewrite).
- Add a **specialist** when the transformation requires cross-file
  reasoning, value-flow analysis, or a judgement call that the Planner's
  retrieved-recipe context isn't enough to inform.

If in doubt: add the recipe first. Watch the corpus for repeated
harvests that look similar; those are the signal that a new specialist
category is earning its keep.

---

## Repo hygiene

- `cargo fmt --all` before committing.
- `cargo build --workspace` and `cargo test --workspace` must be green.
- Conventional commit prefixes in this branch: `stage-N:`, `fix:`,
  `docs:`, `refactor:`.
- Don't commit `.ods/runs.db` or anything under `.ods/runs/`. The
  `.gitignore` already excludes them.
- Don't commit credentials. The only secrets the tool needs
  (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `ODS_APP_PRIVATE_KEY_PEM`,
  `ODS_WEBHOOK_SECRET`) are all env-vars-only.
