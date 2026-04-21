# Recipes — the growing corpus

A **recipe** is a reusable description of a performance-optimisation
pattern. Each one carries a trigger (how to tell when the pattern
applies), a profile signature (what it looks like in `perf` output), an
ordered transformation, and the semantic invariants a patch must
preserve.

Recipes live in three places:

- `recipes/seed/*.yaml` — hand-authored starter recipes, paper-sourced or
  derived from validated wins.
- `recipes/antipatterns/*.yaml` — target-surfacing signals (e.g.
  "Vec::new() inside a for-loop is a smell"); never auto-applied.
- Runtime state in SQLite (default: `.ods/recipes.db`) — everything
  above plus `Candidate` / `Validated` / `Corpus` recipes auto-harvested
  from race wins, and `Hypothesized` recipes proposed by the Explorer.

## Schema

Defined in `crates/ods-recipes/src/schema.rs`:

```yaml
id: <string>                       # unique slug, often "auto-…" or "hyp-…"
name: <string>                     # short human-readable description
category: <OptimizationCategory>   # enum, see below
language: <string>                 # "rust", "go", "python", "ruby",
                                   # "javascript", "typescript", "c", "java"
promotion: <PromotionState>        # see below
trigger:
  ast_pattern: <regex>             # compiled as a regex today;
                                   # future: tree-sitter query
  profile_signature:               # free-form tags; the Discoverer
    - "hot:loop-vec-alloc"         #   matches these fuzzily
    - "syscall:stat>N/readdir"
  naive_alt_ratio_min: <f64|null>  # optional: only fire when a naive
                                   #   alternative outperforms the
                                   #   primitive by at least this ratio
transformation:
  steps:                           # ordered fix instructions,
    - "Hoist Vec allocation out…"  #   pattern-level, not repo-specific
    - "…preserve append order"
verification:
  test_selectors:  []              # optional test-runner filters
  property_seeds:  []              # seeds for DifferentialHarness
  fuzz_minutes:    5               # how many minutes of cargo-fuzz / go-fuzz
  semver_check:    true            # run cargo-semver-checks?
benchmark_template: ""             # optional: scaffolded bench body
success_history:                   # auto-updated on wins
  - repo: "owner/name"
    commit: "abc123"
    speedup: 17.4
    ci_lower_bound: 16.0
    merged: false
    recorded_at: "2026-04-19T…"
negative_history:                  # auto-updated on abstains / rejects
  - repo: "path/or/owner-name"
    target_symbol: "tokenize"
    outcome: abstained | rejected-by-gate | no-measured-speedup | timeout
    recorded_at: "2026-04-19T…"
generalized_from: <RecipeId|null>  # Generalizer link (this recipe is
                                   #   the reusable sibling of ...)
generalized_as:   <RecipeId|null>  # ... or conversely: pointer from
                                   #   specific → generalised form
source_patch_ref: <string|null>    # commit SHA or "research:…" citation
embedding: [f32; 128]              # auto-populated by Store::upsert
```

`OptimizationCategory` values:

- `syscall-elimination`
- `alloc-reduction`
- `fast-path-specialization`
- `algorithmic`
- `validation-removal`
- `caching`
- `dependency-optimization`

`PromotionState` values (ladder order, highest-trust first):

| state | meaning | retrieval weight | how to get there |
|---|---|---|---|
| `Corpus` | shipped default | 4.0 | `Validated` + N extra successes in a rolling window |
| `Validated` | proven across repos, no rollbacks | 3.0 | `Candidate` + ≥3 distinct-repo merged wins with CI lower ≥ 1.15× |
| `Candidate` | one gate-passing win, specific to a repo | 2.0 | auto on first race win (Phase 1 of `harvest_full`) |
| `Seed` | hand-authored (or blessed by a human) | 1.5 | `ods recipes import` / `import-dir` |
| `Hypothesized` | Explorer-proposed or Generalizer-produced; never validated | 0.4 | Explorer run, or Phase 2 of `harvest_full` |
| `AntiPattern` | target-surfacing signal; NEVER auto-applied | 0.0 | hand-authored in `recipes/antipatterns/` |

## The growing-itself loop

```
     ┌─────────────────────────────────────────────────────────────┐
     │                                                             │
     ▼                                                             │
  Explorer (ods explore) ─── Hypothesized ──┐                      │
                                            │                      │
  Seed (human-authored) ────────────────────┼─ Discoverer + Race   │
                                            │      │               │
                                            │      ▼               │
                           if specialist wins, ZeroDiffGate passes │
                                            │      │               │
                                ┌───────────┘      ▼               │
                                ▼          Harvest (Phase 1+2)     │
                           NegativeRecord   ├─ specific auto-…    ─┘
                           on retrieved     │    (Candidate)
                           recipes          └─ generalised sibling
                                                 (Hypothesized,
                                                  generalized_from = …)
                                                             │
                                                             ▼
                                                   promote_on_success
                                                   (Candidate → Validated
                                                    → Corpus)

                        promote_on_negative (Hypothesized only)
                        retires after ≥3 distinct-repo abstains
                        with zero wins
```

Implementations:

- Harvest two-phase: `crates/ods-agents/src/harvest.rs::harvest_full`.
  Phase 1 writes the narrow `auto-<lang>-<cat>-<mod>-<sym>` recipe with
  `success_history = [{repo, commit, …}]` and `source_patch_ref = commit`.
  Phase 2 sends one extra LLM turn with a prompt demanding a
  repo-agnostic pattern description; result upserted as `Hypothesized`
  with `generalized_from = specific_id`; specific then stores
  `generalized_as = general_id`.
- Promote rules: `crates/ods-recipes/src/promote.rs`.
  `promote_on_success` bumps up the ladder monotonically.
  `promote_on_negative` only acts on `Hypothesized`: ≥3 distinct-repo
  abstains with zero wins → `PromotionOutcome::Retire` (the caller
  deletes).
- Negative history emission: `crates/ods-agents/src/race.rs` pushes a
  tuple per failed retrieval into `RaceOutput.negative_records`; the
  orchestrator calls `harvest::record_negatives(…)` to persist.

## Retrieval

Two APIs, both in `crates/ods-recipes/src/store.rs`:

### `Store::search(RecipeQuery) -> Vec<Recipe>`

Symbolic-only. Filters by language + category + promotion floor. Used
when you know exactly what you want (`ods recipes list`, export).

### `Store::retrieve(language, query, limit) -> Vec<(Recipe, f32)>`

The production retrieval path used by the Planner. Pipeline:

1. Symbolic pre-filter: `min_promotion = Hypothesized` (i.e. include
   everything non-anti-pattern), language equality.
2. For each candidate, compute
   `cosine(embed(query), embed(recipe_text)) × retrieval_score(recipe, 5)`.
3. Sort descending by that composite, truncate to `limit`.

Where `retrieval_score(recipe, neg_window) = max(0.1, promotion_weight *
penalty)` and `penalty = 1 - min(neg_count, neg_window) / (neg_window + 1)`
— so a recipe with 5+ negatives in the window gets clamped to the 0.1×
floor (never zero — it can still resurface if a new domain matches).

Embeddings are a 128-dim hash-based feature vector
(`crates/ods-recipes/src/embed.rs`): FNV-1a over token+bigram, signed
feature hashing, L2-normalised. Cosine is a plain dot product after
normalisation. Zero external dependencies.

Future swap point: `sqlite-vec` keeps the interface identical; only the
storage + top-K query changes.

## Authoring a recipe

Three-step recipe for `recipes/seed/rust-my-pattern.yaml`:

```yaml
id: rust-my-pattern
name: short human-readable description
category: alloc-reduction      # pick from the enum
language: rust
promotion: seed

trigger:
  ast_pattern: '<regex>'        # what to grep for
  profile_signature:
    - "alloc:per-iteration"     # free-form; used by the Discoverer
  naive_alt_ratio_min: null

transformation:
  steps:
    - "First concrete step, written for another engineer (or agent)."
    - "Second step."
    - "Invariants to preserve go in the last bullet or a dedicated entry."

verification:
  test_selectors: []
  property_seeds: []
  fuzz_minutes: 0               # 5 if public-API or dep bump
  semver_check: true            # false if the pattern is test-only

benchmark_template: ""

success_history: []
negative_history: []
generalized_from: null
generalized_as: null
source_patch_ref: "research:<source-citation>"
embedding: null                 # auto-populated on upsert
```

Then:

```sh
ods --store .ods/recipes.db recipes import recipes/seed/rust-my-pattern.yaml
```

## Current corpus

(As shipped in `recipes/` at the time of writing.)

### Seed (25 across three languages)

**Rust (21):**
- Blog-derived: `rust-readdir-dtype`, `rust-path-join-fastpath`,
  `rust-chars-count-early-exit`, `rust-bm25-df-hoisted`.
- Research-sourced (allocation, cache, layout):
  `rust-cache-line-pad-shared-atomic`, `rust-smallvec-hot-small-collection`,
  `rust-fxhash-trusted-keys`, `rust-soa-hot-field-scan`,
  `rust-enum-niche-nonzero`, `rust-arena-for-ast-parse`,
  `rust-const-fn-lookup-table`.
- Research-sourced (SIMD / string):
  `rust-memchr-single-byte-search`, `rust-aho-corasick-multi-pattern`,
  `rust-portable-simd-reduction`.
- Research-sourced (branch / async / I/O / numeric):
  `rust-cold-attr-error-paths`, `rust-branchless-hot-select`,
  `rust-futures-unordered-over-join-all`, `rust-spawn-blocking-threshold`,
  `rust-io-uring-batched`, `rust-fma-mul-add`, `rust-loop-tiling`.

**Go (2):** `go-preallocate-slice-make-cap`, `go-sharded-concurrent-map`.

**Python (2):** `python-slots-dataclass`, `python-functools-cache`.

### Anti-patterns (26 across three languages)

**Rust (11):** `ap-rust-loop-vec-alloc`, `ap-rust-format-in-loop`,
`ap-rust-collect-then-iter`, `ap-rust-unconditional-clone-in-loop`,
`ap-rust-nested-for-contains`, `ap-rust-regex-new-in-loop`,
`ap-rust-metadata-is-dir`, `ap-rust-to-string-on-str`,
`ap-rust-read-to-string-loop`, `ap-rust-string-push-str-concat`,
`ap-rust-hashmap-new-in-loop`.

**Go (8):** `ap-go-sprintf-in-loop`, `ap-go-append-to-nil-slice`,
`ap-go-regexp-compile-in-loop`, `ap-go-string-bytes-roundtrip`,
`ap-go-json-unmarshal-in-loop`, `ap-go-defer-in-loop`,
`ap-go-map-string-key-concat`, `ap-go-range-by-value-large-struct`.

**Python (7):** `ap-python-str-concat-loop`, `ap-python-range-len`,
`ap-python-attribute-lookup-in-loop`, `ap-python-re-compile-in-loop`,
`ap-python-list-comp-over-append`, `ap-python-dict-vs-brace`,
`ap-python-len-truthiness`.

## Debugging retrieval

If `ods run` / `ods optimize` doesn't retrieve the recipe you expect:

```sh
# Manual BM25 search (lexical; different from Planner retrieval):
ods --store .ods/recipes.db recipes search "readdir stat syscall"

# Inspect full record including embedding + history:
ods --store .ods/recipes.db recipes show rust-readdir-dtype

# List by language + filter:
ods --store .ods/recipes.db recipes list --language rust
```

To see what the Planner actually retrieved for a specific run, read the
run artifact's `recipes_applied` field or the timeline:

```sh
ods explain path/to/repo <run_id>
ods explain path/to/repo <run_id> --timeline | grep specialist-start
```
