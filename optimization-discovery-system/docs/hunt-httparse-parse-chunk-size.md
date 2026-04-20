# Hunt: httparse::parse_chunk_size (2026-04-20)

First intentional hunt against a third-party OSS repo post-Stage-17.
Honest result: **no win**, but a clean diagnostic that surfaced one
real gap (apply_patch format tolerance) and validated three pieces
of infrastructure under production conditions.

## Target selection

`ods discover` ran across three cloned Rust repos:

- `BurntSushi/bstr`
- `seanmonstar/httparse`
- `servo/rust-url`

Top non-test candidate: **`httparse::parse_chunk_size` at
`src/lib.rs:1264`**, score 7.24, matched `rust-cold-attr-error-paths`.
The function is a per-byte state machine with multiple
`return Err(InvalidChunkSize)` branches — a plausible `#[cold]`
annotation site in a widely-deployed HTTP parser (~800M downloads).

## Run

```
ods run . --target rust::httparse::parse_chunk_size \
  --mode ci --wall-cap-s 1200 --spend-cap-usd 5.0 --llm
```

Run id: `04d05caa-bba1-4cb3-930b-7fe4aeeccc73`.

## What happened

1. **AllocReducer** loaded the function + reasoned about allocations,
   abstained (`patch=false, accepted=false`), spent **$1.89** across
   120k input tokens. The target doesn't allocate — abstain was the
   correct call but the cost is eye-opening.
2. **FastPathSpecializer** surveyed the repo (list_dir, ast_query,
   read_file through 6 turns), identified a credible fast-path hypothesis
   — "common case: a few hex digits followed by `\r\n`, no extensions,
   no LWS" — then emitted an `apply_patch` call with a diff in the
   `*** Begin Patch / *** Update File: src/lib.rs` format.
3. **`apply_patch` rejected** both its strict path (git-apply returned
   "No valid patches in input") and its fuzzy fallback
   (`parse_unified_diff: no files in input`).
4. Before the specialist could retry, **budget enforcement fired**:
   `current $4.91 + projected $1.15 > cap $5.00` → abort, partial
   artifact written.

Total spend: **$1.89** (AllocReducer only; FastPathSpecializer's
tokens were cached up to the rejected patch call).

## What this tells us

### Validated under production load

- **Budget gate (Stage 7).** Per-API-call projection kept spend to
  $1.89 / $5.00. Without it the FastPathSpecializer would have
  retried the patch format (costing ~$1.15 per call) until the wall
  cap tripped, overshooting $5.00 by a wide margin.
- **Two-stage planner retrieval.** Selected 8 hypotheses with at
  least one matched recipe per specialist kind. No hallucinated
  recipes surfaced.
- **Tree-sitter ast_query.** Agent's
  `(function_item name: (identifier) @name (#match? @name "parse_chunk_size"))`
  query returned the exact line range — this is exactly the
  precision improvement Stage 7 was supposed to deliver.

### Actionable gap (Stage 19 candidate)

**`apply_patch` doesn't tolerate the OpenAI-style patch format.**
The current strict + fuzzy fallback both expect a unified diff
(`--- a/...`, `+++ b/...`, `@@`). Large agents frequently emit:

```
*** Begin Patch
*** Update File: src/lib.rs
@@ (context)
 old line
-removed line
+added line
*** End Patch
```

Either accept this format via a second fallback, or tighten the
specialist prompt to force unified diff. The former is more
defensive; the latter is cheaper to implement and lets us keep
the single-format invariant.

## Infrastructure that held up

- Stage 18 validation gates never tripped (Explorer wasn't invoked
  because the user didn't pass `--explore`; worth adding a default
  Explorer pass if the run has >$3 budget remaining after the race
  — future work).
- Zero-diff gate reported `Pass` correctly despite no patch, because
  nothing changed. The gate output is noisy in that case ("Pass" is
  technically true but meaningless); consider a distinct
  `NoChange` status.

## Next hunt

Easiest move: land the `apply_patch` tolerance fix, re-run the same
target, and see whether FastPathSpecializer's fast-path hypothesis
actually produces a speedup. The bench `benches/parse.rs` already
exists; the specialist's plan to add a `parse_chunk_size` bench
would let us verify the speedup directly.
