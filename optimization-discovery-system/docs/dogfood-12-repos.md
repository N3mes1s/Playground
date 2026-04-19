# Dogfood: `ods discover` on 12 top OSS repos

> Running the product end-to-end against three popular public
> repositories per supported language (Rust, Python, Go, Ruby). The
> point isn't to cherry-pick wins — it's to see what the discover
> pipeline actually produces on code it has never seen, and be honest
> about where it over-matches vs where the signal is real.

## What we ran

- Binary: `target/release/ods discover <repo> --json --language <L> --top 200`
- Corpus: the full 61-recipe store (31 seed + 30 antipattern), imported fresh.
- Clones: `git clone --depth=1` on each repo. For three repos
  (`fastapi`, `prometheus`, `rails`) the full tree timed out, so we
  scoped to the canonical library subdirectories (`fastapi/`,
  `cmd+tsdb+storage+promql+`, `activerecord+activesupport`).
- The cap is `--top 200`, so "200 candidates" often means we hit the
  cap rather than exhausted the pool.

## Headline: what fired, how much

| Repo (lang)              | Candidates | Unique recipes |     Top hit                          |
| ------------------------ | ---------- | -------------- | ------------------------------------ |
| BurntSushi/ripgrep (rust)|  200       | 11 + 1 anti    | `rust-path-join-fastpath` ×115       |
| clap-rs/clap (rust)      |  200       | 11 + 1 anti    | `rust-path-join-fastpath` ×134       |
| tokio-rs/tokio (rust)    |  200       | 11 + 1 anti    | `rust-path-join-fastpath` ×104       |
| pallets/flask (python)   |  200       | 1 + 3 antis    | `python-functools-cache` ×200        |
| psf/requests (python)    |  190       | 1 + 6 antis    | `python-functools-cache` ×174        |
| tiangolo/fastapi (python)|  199       | 2 + 5 antis    | `python-functools-cache` ×193        |
| spf13/cobra (go)         |  111       | 0 + 3 antis    | `ap-go-range-by-value-large-struct` ×92  |
| gin-gonic/gin (go)       |  129       | 1 + 2 antis    | `ap-go-range-by-value-large-struct` ×107 |
| prometheus/prometheus (go)|  200      | 1 + 3 antis    | `ap-go-range-by-value-large-struct` ×186 |
| Shopify/bootsnap (ruby)  |   23       | 1 + 2 antis    | `ruby-file-join-string-interp` ×13   |
| jekyll/jekyll (ruby)     |   76       | 2 + 2 antis    | `ruby-file-join-string-interp` ×41   |
| rails/rails (ruby)       |  101       | 2 + 2 antis    | `ruby-file-join-string-interp` ×54   |

Every repo produced candidates. The discover path, the multi-language
dispatch, and the enclosing-symbol attribution all work across 776
`.rs` files (tokio), 2.5k+ `.py` files (fastapi), hundreds of `.go`
files, and hundreds of `.rb` files. **That's the success story.**

The rest of this doc is the failure story — where the signal is
drowned in noise.

## Plausibly-actionable highlights

Things that look like real opportunities a specialist could productively take:

- **ripgrep::walk** (top-scored, 15.0). Matches `rust-enum-niche-nonzero`
  + `rust-struct-layout-pack`. Big struct in a hot traversal path.
- **clap::parse** (19.4). `rust-cold-attr-error-paths` + `rust-debug-only-work-hoist`
  — a hot parse loop with Err-construction and debug!() calls the
  specialist could move behind `log_enabled!`.
- **tokio::create** (13.4). `rust-smallvec-hot-small-collection` in a
  spawn/create path.
- **bootsnap::list_files** (5.5). `ruby-file-join-string-interp` +
  `ap-ruby-directory-check-in-loop`. This is literally the shape
  byroot's post attacked.
- **jekyll::test_utils** (7.5). `ruby-dir-each-child-over-glob-stat`
  fired — the recipe looking for `Dir.glob` / `Dir.entries` inside a
  hot pass, exactly the Bootsnap-style pattern.
- **prometheus::head** (7.9). `go-sharded-concurrent-map` — a
  sync.Mutex + map combo in the TSDB hot path.

These are credible candidates. Whether they'd survive a specialist
run + bench gate is a separate question; the discover step does its
job.

## The noise, named honestly

Four recipes are over-matching in ways that would destroy a real
specialist run:

### 1. `python-functools-cache` — way too broad

Fires on literally any function definition with a `return` statement
(193-200 hits per repo). The trigger is:

```
(function_definition
  name: (identifier) @fn
  body: (block (return_statement))) @match
```

That's "is this a function that returns something." It's not a perf
signal. **Fix:** tighten to "pure function with simple, hashable-looking
args and no attribute mutation in the body." Tree-sitter can get part
of the way there (reject methods that start with `self.` assignments)
but a real implementation needs a more conservative trigger and a
specialist-side applicability check.

### 2. `ap-go-range-by-value-large-struct` — matches every `for range`

Fires 92/107/186 times in our three Go repos. The pattern is
`(for_statement (range_clause))` — every `for k, v := range xs`. The
*real* antipattern is ranging by-value over a slice of structs where
each struct is >64 bytes (the range loop copies each value). Tree-sitter
can't see struct size directly. **Fix:** either (a) tighten to cases
where the range binding is used via a field access (`x.field`, not
`x` itself), which narrows to cases where copying hurts, or (b) demote
this from antipattern to a runtime hint the specialist checks with
`go vet -fieldalignment` or similar.

### 3. `rust-path-join-fastpath` — fires on `.push` / `.join` everywhere

100+ hits per Rust repo. The trigger is `(field_expression field:
(field_identifier) @m (#match? @m "push|join"))` — any method call
named `push` or `join`. `Vec::push`, `String::push`, `Vec::join`,
`join_all`, thread handle `.join()` — all of them. The recipe only
applies when the receiver is a `PathBuf` or `Path`, which tree-sitter
can't resolve without type info. **Fix:** narrow the trigger to the
`PathBuf::` / `Path::` scoped-identifier receivers only, and drop
method-expression false positives. This trades recall (we'll miss
some aliased cases) for precision.

### 4. `ap-ruby-directory-check-in-loop` — drops the "in loop" part

51-12 hits per Ruby repo. The pattern matches every `File.directory?`
call, not just the in-loop ones. The recipe name mentions "in loop"
but the trigger doesn't enforce that. **Fix:** wrap the trigger in a
`(block … (call …))` where the block belongs to a `.each` or `for`
node, so only the actual antipattern shape fires.

## What this tells us about recipe quality

The three **most-firing** recipes in the Rust / Python / Go dogfood are
the three I just listed as over-matching. Our current ranker doesn't
distinguish "recipe fired because it's relevant" from "recipe fired
because the trigger is loose." A specialist that picked the highest-
scored candidate from the flask output would spend its budget chasing
`python-functools-cache` noise.

Two orthogonal improvements would help:

1. **Tighten the four recipes above.** Each is a 10-minute trigger
   edit + a re-run of this dogfood. Precision will go up by a lot.
2. **Add a "precision penalty" to the retrieval score** — if a recipe
   matches >5% of source files it probably triggers on something
   generic. The score could down-weight it automatically. This is a
   ranker change in `discover.rs::scan_with_recipes` that doesn't need
   per-recipe tuning.

## What works well

- **Ruby.** Of the four languages, Ruby has the highest signal-to-noise.
  Total candidate volume per repo is smaller (23-101 vs 200 cap) and
  the recipes that fire are the ones we designed for — `File.join`,
  `Dir.glob` + `File.directory?`, `Regexp.new` in loops. The honesty
  here is that we only have 5 Ruby recipes, so there's less room for
  a noisy one to dominate. But the shapes that do fire are the byroot
  shapes we built Slice A for.
- **Enclosing-symbol attribution.** Every candidate in every repo had
  a real enclosing method/function name (not a file stem). Stage 12
  paid for itself.
- **Multi-language dispatch.** Zero crashes across 12 repos and
  4 grammars. The tree-sitter wiring is solid.

## Next work this motivates

1. **Tighten those four recipes.** Small, cheap, high leverage. Should
   cut noise by ~80%.
2. **Precision-penalty ranker.** Down-weight recipes firing on >5% of
   source files.
3. **Run this dogfood again** after 1+2 and compare top-5 by-score
   lists. Success = the top 5 actually looks interesting to a human.

Out-of-scope for *this* pass but worth flagging:

- Three repos needed manual subdirectory scoping (`fastapi`,
  `prometheus`, `rails`) because the full tree timed out at 5 minutes.
  This is a `Discoverer` scalability issue — we parse every source
  file on every run. Incremental scanning keyed on file mtime would
  turn this into a one-time cost.
- `cobra` fired zero applicable recipes, only antipatterns. Either
  our Go seed corpus is thin (it is — only 2 seeds vs 10 antipatterns)
  or cobra really is pretty clean. Adding 2-3 more Go seeds would
  improve cross-repo recall.
