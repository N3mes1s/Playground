# Architecture

## The Loop (central abstraction)

Every `ods run` walks a typed state machine defined in
`crates/ods-core/src/loop_.rs`:

```
TargetSelect
    │
    ▼
Profile          (build + run_bench + profile via strace / perf)
    │
    ▼
RecipeRetrieve   (Planner queries Store with vector search)
    │
    ▼
Hypothesize     (Planner emits (specialist, hypothesis) pairs)
    │
    ▼
Transform       (--llm: specialist race in parallel worktrees
                 no --llm: measurement-only baseline pass)
    │
    ▼
Verify          (run_tests + fuzz + semver + downstream)
    │
    ▼
Bench           (post-bench + rerun-N determinism gate)
    │
    ▼
Explain         (PR body via ods-report::render_pr_body)
    │
    ▼
Harvest         (specific recipe + Generalizer's reusable sibling)
```

The stages are a plain `enum LoopStage`; `Run::advance()` checks the
autonomy budget (`Mode::Dev` is unbounded, `Mode::Ci { wall_cap,
spend_cap_usd }` is not) at every transition and returns
`LoopError::BudgetExhausted` when over. A partial-result artifact is
still persisted and the run ends gracefully rather than crashing.

## Crate graph

```
ods-cli                    single binary entry (bin = "ods")
  │
  ├─ ods-core              domain types + LoopStage + Mode + git::Worktree
  │                         + run_store (SQLite runs/events)
  ├─ ods-exec              subprocess primitive (timeout + structured capture)
  ├─ ods-recipes           schema + SQLite store + BM25 + hash embeddings
  │                         + retrieve() + promote() + Generalizer links
  ├─ ods-measure           stats (bootstrap CI), rerun-N, env fingerprint,
  │                         pinning, profiler trait
  ├─ ods-verify            zero-diff gate, cargo-semver-checks wrapper,
  │                         downstream test runner, property harness
  ├─ ods-lang              LanguageAdapter trait + Registry
  │
  ├─ ods-lang-rust         Rust adapter: cargo build/test/bench/fuzz,
  │                         strace+perf profiler, cargo-flamegraph,
  │                         criterion-JSON ingestion, bench-scaffolder
  ├─ ods-lang-go           go test / go test -bench / go test -fuzz
  ├─ ods-lang-python       pytest + pytest-benchmark JSON
  ├─ ods-lang-ruby         bundle + minitest / rspec + benchmark-ips
  ├─ ods-lang-c            cmake/make + ctest + google-benchmark stubs
  ├─ ods-lang-js           npm test + tinybench / jest / vitest
  ├─ ods-lang-java         mvn / gradle + surefire/JMH stubs
  │
  ├─ ods-agents            Anthropic client + ToolUseLoop + Planner +
  │                         Specialists (7) + Explorer + Race + Harvest +
  │                         Generalizer + Discoverer + Scheduler +
  │                         Orchestrator + observe (events)
  ├─ ods-ci                GitHub REST client + App JWT auth +
  │                         webhook server + HMAC-SHA256 sig verify
  └─ ods-report            PR body markdown renderer
```

### Dependency direction

`ods-cli` depends on everything. Language-specific crates (`ods-lang-*`)
depend only on `ods-lang` + `ods-core` + `ods-exec`. `ods-agents` depends
on `ods-lang`, `ods-lang-rust` (for the scaffolder — unique), `ods-recipes`,
`ods-measure`, `ods-verify`, `ods-ci`. Never the other way: no `ods-lang-*`
crate knows the agents exist.

This keeps the language adapters embeddable in unrelated tools (someone
could write their own planner on top of `ods-lang-rust` without pulling
`anthropic` deps in).

## Data flow for one run

```
  caller (CLI or Scheduler)
     │   run(target, allow_llm)
     ▼
  Orchestrator (ods-agents/src/orchestrator.rs)
     │
     ├── open .ods/runs.db
     │   insert RunRecord { status: InProgress }
     │   append_event(Start)
     │
     ├─► adapter.build(repo, None)           (ods-lang-rust::RustAdapter)
     │       │
     │       └─► ods-exec::run({cargo, build, --release, ...})
     │
     ├─► adapter.profile(build, target)
     │       │
     │       ├─► strace -c cargo bench ...   (syscall counts)
     │       ├─► perf stat ...               (cycles / insns / cache)
     │       └─► /usr/bin/time -v            (wall, max RSS)
     │
     ├─► adapter.run_bench(build, target)
     │       │
     │       └─► cargo bench -> target/criterion/**/estimates.json
     │                (falls back to stdout regex when JSON missing)
     │
     ├── append_event(Profile, done)
     │
     ├─► [ if pre_bench empty and adapter = rust ]
     │     ods_lang_rust::bench_scaffold::scaffold(...)
     │        → benches/ods_auto_<sym>.rs + Cargo.toml [[bench]] entry
     │        → re-run pre_bench
     │
     ├─► Planner::plan(target, categories)   (ods-agents/src/planner.rs)
     │       │
     │       └─► Store::retrieve(language, query, 8)
     │              │
     │              └─► cosine(embed(query), embed(recipe))
     │                    * retrieval_score(recipe, 5)
     │              returns top-K (recipe, score)
     │
     ├── append_event(RecipeRetrieve, done)
     │
     ├─► [ if allow_llm && ANTHROPIC_API_KEY set ]
     │     race::run_specialists(RaceInput {
     │        plan, pre_bench, sink: SqliteEventSink,
     │        worktree_parent: /tmp/ods-worktrees/<run_id>,
     │        fuzz_budget: 60s, ...
     │     })
     │        │
     │        for each (kind, hypothesis) in plan:
     │           wt = Worktree::create(repo, tag, parent)   # git worktree --detach
     │           loop = ToolUseLoop::default()
     │              .register_read_only(Sandbox::new(wt.path))
     │              .register_mutating(Sandbox::new(wt.path))
     │           (stats, text, convo) = loop.run_observed(
     │              client, specialist_prompt, user_prompt, ObserverSink
     │           )
     │           # every Turn / Reasoning / ToolCall / ToolResult is
     │           # emitted as an AgentEvent to the SqliteEventSink
     │           # (→ .ods/runs.db/run_events table)
     │           extract diff from final text
     │           apply, build, run_tests, fuzz, run_bench in wt
     │           ZeroDiffGate::evaluate(...)
     │           if pass AND speedup_lower > 1.0: candidate
     │        pick winner by highest speedup_lower
     │        for each retrieved recipe that didn't win:
     │           record_negatives(recipe_id, repo, target, outcome)
     │
     ├── append_event(Transform, done)
     │
     ├─► run_tests(build, Full)              (post-transform verification)
     ├── ZeroDiffGate::evaluate
     ├── rerun(3) → RerunReport { cis_overlap, fingerprint_stable }
     │     if either false → pr_withheld = true
     ├── append_event(Verify, done); append_event(Bench, done)
     │
     ├─► harvest::harvest_full(winner, target, repo, commit, store, client)
     │        ├── Phase 1: upsert specific Recipe (Candidate,
     │        │              source_patch_ref = commit)
     │        └── Phase 2: Generalizer LLM call
     │              → upsert generalised Recipe (Hypothesized,
     │                  generalized_from = specific_id)
     │              specific.generalized_as = generalised_id
     │
     ├── persist final artifact JSON to .ods/runs/<run_id>.json
     └── run_store.finish(run_id, RunStatus::Completed, artifact_json)
```

## Persistence layout (under `<repo>/.ods/`)

```
.ods/
├── runs.db                SQLite. Two tables:
│                            runs       (one row per Run, stage + status)
│                            run_events (append-only AgentEvent stream,
│                                        keyed on run_id + seq)
├── runs/
│   └── <run_id>.json      Mirror of the final RunArtifact; human-
│                          readable, what `ods explain <run_id>` prints
│                          and what the GitHub PR body references.
├── batches/
│   └── <batch_id>.json    One file per `ods optimize` invocation,
│                          referencing all child run ids.
└── worktrees/             Only when the orchestrator fell back from
                            `git worktree add --detach` to copy-based
                            worktrees (the default is /tmp/ods-worktrees/
                            to keep them outside the source repo).
```

The separate recipe store (`--store` flag, usually `.ods/recipes.db`) is
independent of the run store. Deleting `.ods/runs.db` discards only run
history; the corpus persists. Deleting `.ods/recipes.db` resets the
corpus.

## Language adapter contract

Every language adapter implements `ods_lang::LanguageAdapter`:

```rust
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
    async fn fuzz(&self, build: &Build, target: &TargetSig,
                  budget: Duration) -> Result<FuzzReport>;
}
```

Detection is best-effort file-system sniffing (`Cargo.toml`, `go.mod`,
`pyproject.toml`, `Gemfile`, `CMakeLists.txt`, `package.json`, `pom.xml`
/ `build.gradle`). First adapter whose `detect()` returns true wins.

`Registry` (`crates/ods-lang/src/registry.rs`) is just an `Arc<dyn
LanguageAdapter>` vec. CLI registers them in a fixed order in
`build_registry()`; feel free to reorder when writing a more opinionated
host.

## Mode + budget enforcement

`ods-core::Mode`:

```rust
pub enum Mode {
    Dev,                       // unbounded
    Ci(Budget),
}

pub struct Budget {
    pub wall_cap: Duration,   // orchestrator aborts on overrun
    pub spend_cap_usd: f64,   // LoopStats::estimated_cost_usd() vs this
}
```

`Run::spent_usd` is updated by the Race after every specialist
conversation (`LoopStats::estimated_cost_usd()` pulls per-million-token
prices from env vars `ODS_INPUT_PRICE_PER_MTOK` / `ODS_OUTPUT_PRICE_PER_MTOK`,
defaults to Opus pricing). `Run::check_budget()` returns
`Err(BudgetExhausted)` when either cap overflows; the orchestrator
catches that, sets `pr_withheld = true`, records the partial-result
artifact, and exits the stage loop.

Because the check is per-stage (not per-token), real spend can overshoot
by the cost of the in-flight specialist. This is observable in the
dogfood logs (spent $6.65 under a $6 cap). See
[operations.md](./operations.md#budget-overshoot) for mitigations.
