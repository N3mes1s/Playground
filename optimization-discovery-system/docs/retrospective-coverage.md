# Retrospective coverage: would ODS have helped?

> A product that claims to surface and apply optimization wins has to be
> honest about which wins it would have actually caught. This document
> walks four well-known public perf writeups through the current ODS
> pipeline and reports where we already cover the pattern, where the
> corpus or adapters fall short, and what the ranked next steps are.

## The exercise

For each case study we ask five questions:

1. **Discovery** — would `ods discover` surface the target without a human pointing at it?
2. **Corpus** — does one of our 51 shipped recipes trigger on this shape?
3. **Specialist** — does a `SpecialistKind` already know how to propose the fix?
4. **Verification** — can `ZeroDiffGate` + the language adapter confirm the invariants held?
5. **Measurement** — can the bench / profile stage prove the win?

"Would ODS have helped" means **yes to 1, 2, 3, 4, and 5**. Partial credit
is explicitly named in the tables.

---

## Case 1 — byroot, *Optimizing Ruby Path Methods* (Apr 2026)

The post that named this project. Two separate wins:

### 1a. `Dir.scan` surfacing `d_type` from `readdir(3)`

|                 | Observation                                                                                                          |
| --------------- | -------------------------------------------------------------------------------------------------------------------- |
| Language        | Ruby (CRuby C impl) + Bootsnap Ruby caller                                                                           |
| Target          | directory scan in Bootsnap's load-path cache builder                                                                 |
| Signal          | `strace` shows N `stat(2)` per entry via `File.directory?` inside a loop                                             |
| Fix             | expose `d_type` from `readdir` via new `Dir.scan` API; callers avoid the follow-up `stat`                            |
| Invariants      | non-ASCII filenames remain correctly classified; FS types that don't populate `d_type` still fall back to `stat`     |
| Win             | 2.16× speedup (230 ms vs 500 ms on 32 k files)                                                                       |

**ODS today:**

| Step          | Verdict      | Notes                                                                                                           |
| ------------- | ------------ | --------------------------------------------------------------------------------------------------------------- |
| Discovery     | ❌ miss       | `ods-lang-ruby` is a stub. No tree-sitter-ruby. `.rb` files aren't parsed, so the `File.directory?`-in-loop shape never matches. |
| Corpus        | ⚠ partial    | `rust-readdir-dtype` is the right SHAPE but the `language: rust` filter drops it before it reaches a Ruby file. |
| Specialist    | ✅            | `SyscallEliminator` category is correct.                                                                         |
| Verification  | ❌            | Ruby adapter's `run_tests` and `run_bench` are not functional.                                                   |
| Measurement   | ⚠ partial    | `strace -c` would work on the child process; our `profile.rs` doesn't wire it for Ruby.                          |

### 1b. `File.join` ASCII fast path

|            | Observation                                                                                                      |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Language   | C (CRuby impl)                                                                                                   |
| Target     | `rb_file_s_join`                                                                                                  |
| Signal     | `perf` flamegraph: 33% of wall in `rb_enc_mbclen` called per byte                                                 |
| Fix        | detect ASCII-compatible encodings (UTF-8, US-ASCII) → skip multi-byte width lookup; reverse-scan trailing seps    |
| Invariants | Shift-JIS (`0x5c` byte collides with `/`) must NOT take the fast path; null-byte detection preserved              |
| Win        | 7.80× for two-string case; 21.75 M vs prior 2.79 M ops/sec                                                       |

**ODS today:**

| Step          | Verdict   | Notes                                                                                                        |
| ------------- | --------- | ------------------------------------------------------------------------------------------------------------ |
| Discovery     | ❌ miss    | `ods-lang-c` is a stub. No tree-sitter-c. No way to navigate the CRuby source.                               |
| Corpus        | ⚠ partial | `rust-path-join-fastpath` encodes the Rust-side version of the same idea; no C equivalent.                    |
| Specialist    | ✅         | `FastPathSpecializer` is the right category.                                                                  |
| Verification  | ❌         | No C build pipeline, no CRuby make rules wired.                                                               |
| Measurement   | ❌         | CRuby's benchmarks are in `benchmark/` with a bespoke runner; our Discoverer doesn't recognise the harness.   |

---

## Case 2 — nnethercote, *How to speed up the Rust compiler in December 2025*

Five concrete wins landed in rustc. Three are structurally interesting:

### 2a. `#142095` — VecCache first-segment fast path

| Field         | Value                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------- |
| Pattern       | hot lookup serviced by a segmented cache; 99% of keys fit in segment 0                              |
| Fix           | branch on `key < 4096` before computing the segment index                                           |
| Signal        | icount regression analysis across the perf suite                                                    |

| Step          | Verdict   | Notes                                                                                                 |
| ------------- | --------- | ----------------------------------------------------------------------------------------------------- |
| Discovery     | ❌         | Rustc bench data lives in **rustc-perf**, a separate repo. Our Discoverer reads local `benches/` only.|
| Corpus        | ⚠ partial | `rust-smallvec-hot-small-collection` is in the family but doesn't capture "segmented collection". No generic `fast-path-delegate` recipe. |
| Specialist    | ✅         | `FastPathSpecializer`.                                                                                 |
| Verification  | ✅         | Rust adapter handles the build + tests + bench path cleanly.                                           |
| Measurement   | ⚠         | Our bench harness uses wall clock; rustc uses icount. No LLVM-instrumented measurement mode.           |

### 2b. `#147293` — debug computation elimination

The hot path computed a value solely for debug logging. The log line was
almost never enabled.

| Step          | Verdict   | Notes                                                                                                 |
| ------------- | --------- | ----------------------------------------------------------------------------------------------------- |
| Discovery     | ⚠ partial | No recipe triggers on `if log::log_enabled!(…) { … }` absence. Easy to add.                          |
| Corpus        | ❌ missing | No recipe for "work done unconditionally for rarely-enabled log statement". **New recipe opportunity.** |
| Specialist    | ✅         | `FastPathSpecializer` fits — hot path vs rare path.                                                    |
| Verification  | ✅         | Behaviour is identical when logs disabled; trivial to gate.                                             |
| Measurement   | ✅         | Criterion bench picks it up.                                                                            |

### 2c. `#148789` — `format_args!()` layout compaction

30–38% icount win on large workspaces via repacking the `Arguments`
struct.

| Step          | Verdict   | Notes                                                                                                 |
| ------------- | --------- | ----------------------------------------------------------------------------------------------------- |
| Discovery     | ❌         | No trigger for "struct with many fields, each used from a hot loop".                                   |
| Corpus        | ❌ missing | No recipe for "struct-of-arrays layout" or "cache-line packing". Adjacent: `rust-cache-line-pad-shared-atomic`. |
| Specialist    | ⚠         | Closest is `AlgorithmicFixer`; a dedicated `LayoutPacker` would be cleaner.                            |
| Verification  | ✅         | Rust gate handles the invariant via tests + semver.                                                    |
| Measurement   | ⚠         | Needs cache-miss instrumentation (`perf stat LLC-load-misses` does exist in our profile.rs).           |

---

## Case 3 — Instagram, *Dismissing Python Garbage Collection at Instagram*

Two-line config fix (`gc.set_threshold(0, 0, 0)` in pre-fork +
`atexit(gc.disable)`) → 10% CPU efficiency on the fleet via LLC hit-rate
improvement from preserved copy-on-write pages.

| Step          | Verdict     | Notes                                                                                                                   |
| ------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------- |
| Discovery     | ❌           | This is a WSGI/Gunicorn config tweak. Our Discoverer only matches source-level patterns, not runtime boot hooks.         |
| Corpus        | ❌ missing   | No `runtime-config` category. Our seven categories are all code-level.                                                   |
| Specialist    | ❌           | No specialist kind for "propose a one-shot runtime config change".                                                       |
| Verification  | ❌           | Disabling GC is a **behaviour change** (objects leak until fork). Our `ZeroDiffGate` would pass the test suite then break in production because the win is fleet-level, not request-level. |
| Measurement   | ❌           | We measure wall-clock per bench. The real win was LLC hit-rate across forked workers — cross-process metric we don't model. |

This is the case where ODS is **structurally unable** to help today.
Adding it requires a new category and a different verification story
(canary + RSS / page-fault delta).

---

## Case 4 — BurntSushi, *memchr (README + talks)*

Replace stdlib byte-search with `memchr::memmem::Finder`, hoist finder
construction out of the loop.

|               | Observation                                                                                |
| ------------- | ------------------------------------------------------------------------------------------ |
| Pattern       | `haystack.iter().position(|&b| b == NEEDLE)` or naïve substring scan                       |
| Fix           | `memchr::memchr(NEEDLE, haystack)` or `Finder::new(…)` hoisted before the loop             |
| Signal        | disassembly shows no `vpcmpeqb`; IPC < 1.5 on byte-scan inner loop                         |
| Win           | 6.5× on typical workloads                                                                  |

**ODS today:**

| Step          | Verdict   | Notes                                                                                                                        |
| ------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Discovery     | ✅         | `rust-memchr-single-byte-search` trigger matches `iter().position(|&_| _ == lit)` **exactly**.                               |
| Corpus        | ✅         | Recipe exists and is tagged `algorithmic`.                                                                                   |
| Specialist    | ✅         | `DependencyOptimizer` handles adding the `memchr` crate + `AlgorithmicFixer` handles the call-site rewrite.                   |
| Verification  | ✅         | Full Rust gate: tests + fuzz on byte inputs + semver check.                                                                   |
| Measurement   | ✅         | Criterion bench + `perf stat` pick up the IPC improvement.                                                                    |
| Gap           | ⚠ partial | The recipe doesn't capture the "hoist `Finder::new` out of the loop" part. The subtler case is missed.                       |

**This is the one case where ODS as it stands today probably ships a PR end-to-end without human intervention.**

---

## Aggregated gaps, ranked by leverage

| # | Gap                                                                                        | Unlock                                                                      | Rough effort |
| - | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | ------------ |
| 1 | **Ruby + C adapters are stubs; no tree-sitter grammars, no recipes**                        | covers byroot 1a + 1b, the posts that named this project                    | 2–3 days     |
| 2 | **Bench harnesses external to the repo** (rustc-perf, CRuby `benchmark/`)                   | unlocks compiler-sized projects                                             | 1 day        |
| 3 | **No "runtime-config" category**                                                            | Instagram-shape wins (GC tuning, allocator selection, FD-cache, pre-fork)   | 1 day        |
| 4 | **Recipe gaps within Rust**: `debug-only-work-behind-log-level`, `struct-layout-pack`, `fast-path-delegate` | three more rustc-shaped wins per run                                        | 2 h per recipe |
| 5 | **Gate doesn't model "fleet-level behaviour change"**                                       | Lets us *safely* ship GC-tweak-class wins                                   | 2–3 days     |
| 6 | **No instruction-count measurement mode**                                                   | rustc / compiler projects measure in icount, not wall-clock                 | 1 day (wrap `perf stat -e instructions`) |
| 7 | **Recipe-level "hoist setup out of loop" refinement** (memchr Finder case)                  | turns partial memchr coverage into full coverage                            | 2 h          |

## Proposed next slices

Given that our stated goal is "have existed when these posts were
written", the ranking is unambiguous:

- **Slice A** (biggest single unlock): wire **tree-sitter-ruby** into
  the Ruby adapter, build a small Ruby recipe seed (5 recipes covering
  the byroot patterns), port `rust-readdir-dtype` + `rust-path-join-fastpath`
  to Ruby siblings. This alone moves two of four case studies from "miss"
  to "candidate". Effort: ~1 day for the grammar + 1 day for the recipes.

- **Slice B**: three new Rust recipes (`debug-only-work-hoist`,
  `struct-layout-pack`, `fast-path-delegate-when-key-fits-common-range`)
  plus the "hoist memchr Finder" refinement. ~1 day total. Turns 3 of
  the 5 rustc wins into candidates.

- **Slice C**: add `OptimizationCategory::RuntimeConfig` +
  `SpecialistKind::RuntimeConfigurator` + a canary-style verification
  arm. Complex because the gate needs a different story (RSS/page-fault
  metric), but this is the only way we cover Instagram-shape wins at
  all. ~3 days.

Slice A > B > C by a factor of leverage-per-day.
