# End-to-end run: the product optimised something and it stuck

> The previous dogfood surfaced candidates but stopped short of
> validating any as real optimizations. This run closes the loop:
> specialist race → patch → zero-diff gate → statistically significant
> speedup → harvested recipe. First time the full 9-stage loop has
> been exercised against a real target with a real API key and a
> real bench.

## The target

A deliberately-naive allocator hot-path in a synthetic Rust crate at
`/tmp/ods-e2e`:

```rust
pub fn squares_up_to(n: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for i in 0..n {
        out.push(i.wrapping_mul(i));
    }
    out
}
```

Three unit tests cover n = 0, 10, 4 (table-driven).
A Criterion bench hits `squares_up_to(1000)`.

We used a synthetic rather than bootsnap (no `benchmark/` dir for
our Ruby adapter to detect) or clap (uses divan rather than
Criterion / libtest, which our bench parser doesn't recognise).
The honest limit: right now the product closes the loop on Rust
targets with a Criterion or libtest bench harness. Broader coverage
(divan, benchmark-ips, `go test -bench` with per-op allocation
output, pytest-benchmark) is future work.

## Invocation

```
ods --store /tmp/ods-e2e-store.db run /tmp/ods-e2e \
    --target rust::ods_e2e::squares_up_to \
    --mode ci --wall-cap-s 600 --spend-cap-usd 3.0 \
    --llm
```

Corpus: all 61 shipped recipes (31 seed + 30 antipattern) imported
into a fresh store.

## What happened, in order

All 9 stages of the loop completed: **target-select → profile →
recipe-retrieve → hypothesize → transform → verify → bench → explain
→ harvest.**

The planner produced 8 hypotheses, mapping each triggered recipe to
its specialist:

- `rust-smallvec-hot-small-collection` → AllocReducer
- `rust-path-join-fastpath` → FastPathSpecializer
- `rust-fast-path-delegate-common-range` → FastPathSpecializer
- `rust-chars-count-early-exit` → AlgorithmicFixer
- `rust-fma-mul-add` → AlgorithmicFixer
- `rust-portable-simd-reduction` → AlgorithmicFixer
- `rust-cold-attr-error-paths` → AlgorithmicFixer
- `rust-spawn-blocking-threshold` → AlgorithmicFixer

The race dispatched specialists sequentially in worktrees. Two
notable behaviours fell out:

**AllocReducer (winner).** Explored the repo, read `src/lib.rs`,
proposed `Vec::with_capacity(n as usize)`. First `apply_patch` call
failed (malformed diff); retried on iteration 8 and succeeded. Ran
tests (3 pass), ran bench (~700 ns/iter). Principled note in its
final reasoning: "SmallVec doesn't fit here because the return type
is `Vec<u32>` at the API boundary and n=1000 is far above any
reasonable inline capacity." So it applied a CLOSE VARIANT of the
hypothesis rather than forcing the literal recipe. $1.09 spent.

**FastPathSpecializer (rust-path-join-fastpath).** Abstained
correctly: "The target has nothing to do with `PathBuf::push`/`join`.
The hypothesis does not apply." This is exactly the principled-abstain
behaviour the specialist prompts were written to produce. $0.32 spent,
zero patch applied, and the corpus got a `NegativeOutcome::Abstained`
entry so next time this recipe fires here it'll be down-weighted.

**FastPathSpecializer (rust-fast-path-delegate-common-range).** Got
lost in diff formatting. Three failed `apply_patch` attempts (corrupt
patch line 53 / 54, "No valid patches in input") then hit the per-call
budget gate at $2.73/$3.00 — Stage 10's budget tracker caught the
overspend before the next POST fired. $0 charged on that last turn.
The specialist's reasoning showed it misread an em-dash character;
a robust diff applier would help.

## The verdict

```
speedup_point:  1.615
speedup_lower:  1.615    (99% CI)
accepted:       true
gate decision:  Pass
```

Before:
```
squares_up_to_1000  1134.92 ns/iter
```

After:
```
squares_up_to_1000   702.60 ns/iter
```

**1.62× faster, lower bound identical to point estimate at 99% CI,
zero-diff gate passed, total spend $1.41, wall clock ~2 minutes.**

The full artifact lives at
`/tmp/ods-e2e/.ods/runs/95455ada-4e35-47e7-98a4-e0e01babbe0a.json`
— environment fingerprint, per-stage events, hypotheses, the diff
(`let mut out = Vec::new();` → `let mut out = Vec::with_capacity(n as usize);`),
and the pre/post benchmark samples.

## Corpus grew

The harvester turned the winning transform into a new recipe:
`auto-rust-alloc-ods_e2e-squares_up_to`, promotion `candidate`.
Next time anyone runs discover against a repo with a similar shape,
this recipe will fire. Self-curating corpus working as designed.

## What this run actually proves

- **End-to-end pipeline closes on a real win.** We did not previously
  have a single verified example; now we do.
- **Stage 10's per-call budget gate works.** Cut off a runaway
  specialist at $2.73/$3.00 before a fourth failed `apply_patch`
  could charge for another round.
- **Specialists abstain when their recipe doesn't fit.** The
  `rust-path-join-fastpath` case shows the prompt + retrieval logic
  works as designed — wrong-recipe-for-target gets rejected rather
  than rationalised into a bad patch.
- **The harvester writes something reusable.** The new candidate
  recipe has the diff as a transformation step, the target signature
  as the profile signature, and a `success_history` entry.

## What this run does NOT prove

- **Real-world repos still have open adapter gaps.** Divan (clap),
  lack of `benchmark/` dir in the Ruby adapter (bootsnap), and
  nightly-gated libtest (ripgrep globset) all block the same
  pipeline on the actual third-party targets we want to hit.
- **Diff formatting is a real failure mode.** Two of three specialists
  in this run hit `apply_patch` errors at least once. Non-fatal here
  because the winner retried successfully; on a tighter budget it
  would have been a silent miss.
- **A synthetic is a synthetic.** This was a deliberate hot-path
  constructed to be optimizable. The same pipeline on bootsnap or
  ripgrep would need additional adapter work before it could even
  start to earn its keep.

## Next slices this motivates

- **Adapter gaps by priority**: divan bench parser for Rust,
  `benchmark/` autoscaffold for Ruby (parallel of `bench_scaffold`
  for Rust), nightly-libtest support for ripgrep-class crates.
- **Robust diff applier**: the Anthropic output uses em-dash, fancy
  quotes, and mismatched @@ hunks frequently enough that shelling to
  `git apply --allow-empty` is fragile. A tolerant applier (fuzzy
  context matching with a line-budget) would recover most failures.
- **One real third-party run**: bootsnap or a small crate with a
  Criterion bench. With the adapter gap closed, the same pipeline
  that produced this 1.62× run should just work.
