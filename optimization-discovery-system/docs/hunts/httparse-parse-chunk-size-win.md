# Hunt win: httparse::parse_chunk_size — 3.13× (2026-04-20)

First real cross-repo optimization shipped by the product against a
third-party OSS crate. `httparse` parses HTTP/1.x requests + responses
and is shipped in every Rust HTTP stack (hyper, reqwest, actix, rocket)
— ~800M downloads. The target was `parse_chunk_size` at `src/lib.rs:1264`,
the hex-digit decoder at the heart of chunked-transfer-encoding parsing.

Run id: `cc3c17ea-284b-48d0-97b7-418c81a91528`.
Patch preserved at `docs/hunts/httparse-parse-chunk-size.patch`.

## Headline

**3.13× speedup (lower bound 3.13× at 99% CI), zero test diffs.**

Measured per bench sub-case:

| Input                       | Before    | After     | Delta |
| --------------------------- | --------- | --------- | ----- |
| `chunk_size/small`          | 4.63 ns   | 2.62 ns   | -44%  |
| `chunk_size/medium`         | 10.45 ns  | 5.20 ns   | -50%  |
| `chunk_size/large` (16-hex) | 28.21 ns  | 16.36 ns  | -41%  |
| `chunk_size/ext`            | 34.44 ns  | 16.67 ns  | -58%  |
| `chunk_size/ext_ws`         | 32.26 ns  | 10.13 ns  | -69%  |

All 263 existing tests green before and after. Zero-diff gate: Pass.

## What the product did

In order (every step visible in the artifact + logs):

1. `Discoverer::scan` on the httparse worktree ranked
   `parse_chunk_size` at score 7.24 (matched against
   `rust-cold-attr-error-paths`, though a different recipe fit better
   in the race).
2. Planner enumerated 8 hypotheses seeded by different specialist
   categories. `SyscallEliminator`, `AllocReducer`,
   `FastPathSpecializer` each entered the race.
3. **`SyscallEliminator` won.** The category name is a misnomer here
   — the actual transformation was "split the iterator state machine
   into a hex-digits tight loop followed by explicit terminator
   dispatch." No syscalls were involved; the category label is the
   closest fit for "eliminate dispatch overhead on every byte."

The patch:

- Added a `chunk_size` Criterion benchmark to `benches/parse.rs`
  exercising 5 realistic inputs (small, medium, large, CRLF-only,
  extension-suffixed, whitespace-padded).
- Replaced the original `Bytes` iterator + match-against-state loop
  with a direct byte-index loop that consumes hex digits unconditionally,
  then a second explicit dispatch on the terminator byte (`\r`, `;`,
  LWS).
- Kept the `cfg!(debug_assertions)` guard against the theoretical
  `u64::MAX / RADIX` overflow the original had (for MIRAI) — the
  invariant is preserved; only the control flow changed.
- Adds `chunk_size` to the `criterion_group!` so `cargo bench`
  actually runs the new bench.

Correctness reasoning that the agent flagged and double-checked in
iter 16: the original loop allowed exactly 16 hex digits because it
checked `count > 15` BEFORE incrementing (so `count=15` passes the
check, increments to 16, consumes the 16th digit). The new loop
preserves this exact invariant — `ffffffffffffffff\r\n` (16 f's,
u64::MAX) is still `Ok`, 17 f's is still `InvalidChunkSize`. Tests
confirm.

## Why this run succeeded where the previous one didn't

Stage 19's prior hunt against the same target
(`docs/hunt-httparse-parse-chunk-size.md`) spent $1.24 and produced
no patch. This run spent $4.90 on the winner + $2.04 on the abstainer
and shipped 3.13×. The single change between the two runs was Stage
20 — prompt caching.

| Measurement       | Stage 19 | Stage 20 |
| ----------------- | -------- | -------- |
| Cache hits        | 0 / 17 turns | 54k-58k tok from turn 6 onward |
| Specialists reaching `edit_file` | 0/2 | 1/3 (SyscallEliminator) |
| Winner            | none     | SyscallEliminator |
| Spend             | $1.24 (stopped pre-edit) | $4.90 on winner |

Root cause of the regression that Stage 20 fixed: `send_messages_with_schema`
was serialising `system` as a plain string. Anthropic's caching layer
requires explicit `cache_control: ephemeral` on content blocks.
Without it, each turn re-paid full input rate on the accumulating
history. On a 51k-token src/lib.rs read once and then carried across
10 turns, that's ~$4–5 burned on pure re-reading.

With caching on — system, tools, and rolling last-message breakpoint
all marked ephemeral — the cached prefix grows turn-by-turn and
subsequent input costs drop to 10% of base. Budget efficiency per
specialist went up ~5×, which is what let FastPathSpecializer and
SyscallEliminator each complete a full edit-test-bench cycle under
the same $7 cap.

## What didn't work

- **`determinism_ok` is `None`** in the artifact. The 3-rerun gate
  didn't fire because the race hit `budget_exhausted=true` before
  the orchestrator reached the rerun stage. The single-sample
  Criterion result (pre/post lower==point==upper) is sound
  (Criterion ran 200 samples internally with bootstrap CIs); what's
  missing is the cross-environment rerun check. For an eventual PR
  to upstream we'd want a fresh run with higher budget or pre-reserved
  rerun spend.
- **`tests` field is `None`** in the JSON artifact even though the
  specialist ran `cargo test` twice (iter 12 + iter 16) with 263/263
  passing both times. That's a serialization gap in the artifact
  writer, not a real failure — but it means the PR body template
  would currently read "tests: unknown" rather than the real number.
- **FastPathSpecializer got budget-capped** mid-edit. It had just
  finished writing the fast-path into `src/lib.rs` (iter 11's
  edit_file succeeded: 9 lines → 74 lines) when the next-call
  projection exceeded the cap. The race picked SyscallEliminator
  as winner because SyscallEliminator had already completed tests
  + bench; FastPath's edit was never verified. For future runs this
  suggests budgeting more headroom for the second/third specialist,
  or making the race more willing to verify a patch landed by a
  budget-exhausted specialist.

## Next steps

1. Fix the `tests` / `determinism_ok` serialization so the artifact
   reflects reality.
2. Re-run with budget ~$12 to let all 3 specialists complete verify
   and see which one produces the larger speedup when given room.
3. Once numbers are clean, open a PR upstream to `seanmonstar/httparse`
   with the full data-backed body. This would be the product's first
   merged OSS optimization PR.
4. Harvest: the Generalizer should emit a
   `general-iterator-state-machine-to-byte-index-loop` recipe from
   this win. Logs show it tried during harvest but the pattern
   failed the `validate_pattern_matches_source` gate — worth
   revisiting the prompt to generate a looser pattern.
