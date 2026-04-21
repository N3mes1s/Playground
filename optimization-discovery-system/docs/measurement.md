# Measurement

`ods` is built around one rule: **every speedup claim is backed by a statistically
significant pre/post delta on a locked-down host, captured by a fingerprinted
environment, and replayable N times.** This document covers the machinery that
makes that rule enforceable.

The two crates that matter here are:

- `ods-measure/` — profiler trait, statistics, fingerprint, rerun gate, CPU pinning.
- `ods-lang-rust/` — Rust-specific bench scaffold, Criterion JSON ingestion,
  flame-graph capture, subprocess profiler.

---

## Profile report — the shared shape

Every profiler (current or future) fills the same [`ProfileReport`] struct from
`ods-lang/src/lib.rs`:

```rust
pub struct ProfileReport {
    pub wall: Duration,
    pub cycles: Option<u64>,
    pub instructions: Option<u64>,
    pub llc_misses: Option<u64>,
    pub branch_misses: Option<u64>,
    pub syscall_counts: Vec<(String, u64)>,
    pub alloc_count: Option<u64>,
    pub alloc_bytes: Option<u64>,
    pub flame_svg_path: Option<PathBuf>,
}
```

Missing fields are represented as `None` / empty, never as zero — absence and
zero syscalls are different things.

### Profile gate

`ods-measure::ProfileGate::validate` asserts that critical fields are
present on platforms where they should be. On Linux CI runners it requires
`cycles`, at least one syscall count, and the allocation counters. On macOS
and other platforms everything becomes soft (the gate accepts `None`). See
`crates/ods-measure/src/profiler.rs:15`.

---

## Rust profiler — subprocess strategy

Source: `crates/ods-lang-rust/src/profile.rs`.

The stage-1 profiler doesn't link `libbpf` or open `perf_event_open`
directly. It runs `cargo bench --workspace -- <symbol>` three times, once
wrapped by each available tool, and merges the results into a single
`ProfileReport`:

| Wrapper          | Populates                                         | Fallback      |
|------------------|---------------------------------------------------|---------------|
| `/usr/bin/time -v` | `wall`                                          | silent skip   |
| `strace -c -f`    | `syscall_counts`                                 | silent skip   |
| `perf stat -e cycles,instructions,LLC-load-misses,branch-misses` | `cycles`, `instructions`, `llc_misses`, `branch_misses` | silent skip |

Each wrapper is `tokio`-spawned with a 15-minute timeout and `allow_nonzero`
(we want results even if the inner process exits non-zero, e.g. a bench
panic). Parsers live next to the profiler:

- `parse_time_elapsed` — handles `h:mm:ss`, `m:ss`, and raw `s.s` shapes
  emitted by GNU `time`.
- `parse_strace_c` — parses the `strace -c` tabular summary, dropping the
  `total` row.
- `fill_perf_stat` — anchored on the exact counter names we asked for.

All three parsers have unit tests in `profile.rs` using real stderr
snippets — the format is stable enough across distros that regex is
sufficient. eBPF-based alloc/syscall probing is a stage-2 swap-in behind the
same seam.

### Why subprocess, not a library

Three reasons:

1. musl single-binary story. `libbpf` drags in `libelf`, `zlib`, kernel
   headers. We'd blow the "one static binary you `curl` into CI" promise.
2. `perf_event_open` requires `CAP_PERFMON` or a permissive
   `kernel.perf_event_paranoid`. Shelling out lets the failure mode remain
   "this field is `None`" instead of "the binary crashed".
3. Wrapping `strace -c` is how every perf reviewer on the planet reads
   syscall summaries. Matching their mental model makes the PR body readable.

---

## Benches — two sources, one shape

Rust projects either already have a bench harness or they don't. Both paths
land in the same `BenchReport`.

### Path A: existing Criterion bench

Source: `crates/ods-lang-rust/src/criterion_json.rs`.

Criterion writes `target/criterion/<bench-name>/new/estimates.json` containing
`{mean: {point_estimate, confidence_interval: {lower_bound, upper_bound,
confidence_level}}}`. After `cargo bench` completes, we walk that tree with
`criterion_json::collect` and convert it into `Vec<BenchSample>`. We prefer
the JSON over the stdout regex because:

- it includes a real confidence interval,
- it survives locale differences (comma vs period),
- it doesn't care about console colour codes.

The stdout parser in `parse_cargo_bench_output` is kept as a fallback for
libtest benchers and Criterion runs whose JSON was already cleaned up.

### Path B: no bench — scaffold one

Source: `crates/ods-lang-rust/src/bench_scaffold.rs`.

If the target repo has no `benches/` dir and no `[[bench]]` block in
`Cargo.toml`, the adapter scaffolds a minimal Criterion harness on the fly:

1. Find the right crate — walk `crates/<module>/Cargo.toml` or fall back to
   the workspace root (`locate_target_crate`).
2. Write `benches/ods_auto_<symbol>.rs` with a `criterion_group!` +
   `criterion_main!` pair.
3. Add `criterion = { version = "0.5", default-features = false }` under
   `[dev-dependencies]` if it isn't already there.
4. Append a `[[bench]]` block registering the new file with
   `harness = false`.

The scaffold is **idempotent**: re-running won't duplicate the bench or the
dep. The generated file has a deliberate `black_box(())` no-op body and a
prominent comment block instructing the specialist agent to rewrite
`b.iter(...)` with a realistic fixture before claiming any speedup. The race
winner's patch is expected to include the bench-body rewrite alongside the
real optimisation.

Reviewers are told in the PR body that the scaffolded bench is meant to
*stay* — it's a durable improvement to the repo, not a temporary fixture.

---

## Statistical comparison

Source: `crates/ods-measure/src/stats.rs`.

### Sample

```rust
pub struct Sample { pub name: String, pub values_ns: Vec<f64> }
```

Filled from either Criterion's per-iteration times or libtest's
`ns/iter` median × sample count.

### Bootstrap confidence interval

`bootstrap_ci(values, confidence=0.99, iters=2000, seed)` resamples the
input `iters` times with replacement, computes the mean of each resample,
and returns the (alpha/2, 1-alpha/2) percentiles. We use a deterministic
`XorShift64` PRNG seeded with two fixed constants (`0xC0FFEE` for pre,
`0xDEADBEEF` for post) so repeated `compare` calls on the same input
produce byte-identical CIs. No external RNG dep, no non-determinism.

### Tukey outlier filter

Before bootstrapping, `tukey_filter` drops values outside the 1.5×IQR
fences. This is Criterion-compatible behaviour and catches the common
"one cold sample is 10× the rest" artefact. Samples of size < 4 skip the
filter.

### Speedup verdict

```rust
pub struct SpeedupVerdict {
    pub pre: ConfidenceInterval,
    pub post: ConfidenceInterval,
    pub speedup_point: f64,
    pub speedup_lower: f64,
    pub accepted: bool,
    pub note: String,
}
```

- `speedup_point` = `pre.point / post.point`
- `speedup_lower` = `pre.lower / post.upper` (the conservative lower bound
  on the improvement)
- `accepted` = `post.upper < pre.lower` — the post-change upper bound must
  be strictly below the pre-change lower bound. If the CIs overlap at all,
  `accepted = false`. No p-values, no hand-wavy "probably faster".

The `ZeroDiffGate` in `ods-verify` rejects any race winner whose verdict is
not `accepted`.

---

## Environment fingerprint

Source: `crates/ods-measure/src/fingerprint.rs`.

Every measurement captures an `EnvFingerprint`:

```rust
pub struct EnvFingerprint {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,          // /proc/sys/kernel/osrelease
    pub cpu_model: Option<String>,       // /proc/cpuinfo "model name"
    pub cpu_count: Option<u32>,
    pub cpu_governor: Option<String>,    // cpu0/cpufreq/scaling_governor
    pub aslr_disabled: bool,             // /proc/sys/kernel/randomize_va_space == 0
    pub turbo_disabled: bool,            // intel_pstate/no_turbo or cpufreq/boost
    pub perf_event_paranoid: Option<i32>,
}
```

Capture is **file-system only** — no subprocesses, no IOCTLs. It's cheap
enough to call per sample.

### `diff` and `is_locked`

- `a.diff(&b) -> Vec<&'static str>` — returns the list of field names that
  differ between two fingerprints. Empty list means the measurements are
  environmentally comparable.
- `fp.is_locked() -> bool` — true when both `aslr_disabled` and
  `turbo_disabled` are set. Used by the zero-diff gate to decide whether to
  downgrade a verdict from "accepted" to "accepted-but-noted-as-soft".

Every persisted run stores the fingerprint in `.ods/runs/<id>.json` so
re-runs can verify nothing moved.

---

## Determinism assertion

Source: `crates/ods-measure/src/pinning.rs`.

```rust
pub enum AssertVerdict {
    Locked,
    Soft(Vec<String>),      // reasons we can't guarantee determinism
}

pub fn assert_determinism() -> AssertVerdict;
```

Checks:

1. `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor == "performance"`
2. `/proc/sys/kernel/perf_event_paranoid <= 2`

Failures become `Soft` reasons attached to the report — the run still
proceeds, but the PR body surfaces the reasons so reviewers know why CIs
might be wider than usual.

### CPU pinning

`taskset_prefix(cpu, cmd, args)` composes an argv like
`["taskset", "-c", "3", "cargo", "bench", ...]` when `taskset` is on PATH,
and silently falls back to the unwrapped command otherwise. Callers are
responsible for executing the composed argv — the helper is format-only so
it's trivially unit-testable.

---

## Rerun-N gate

Source: `crates/ods-measure/src/rerun.rs`.

```rust
pub fn rerun<F>(n: u32, mut measure: F) -> RerunReport
where F: FnMut() -> (Sample, Sample);
```

Runs the closure `n` times, each time producing a (pre, post) pair. Returns:

```rust
pub struct RerunReport {
    pub n: u32,
    pub verdicts: Vec<SpeedupVerdict>,
    pub fingerprint: EnvFingerprint,
    pub fingerprint_stable: bool,
    pub all_accepted: bool,
    pub cis_overlap: bool,
}
```

Acceptance requires **three** things:

1. `all_accepted` — every individual run's verdict is `accepted`.
2. `cis_overlap` — every pair of post-change CIs has a non-empty
   intersection (`max(lower) <= min(upper)`). If the 3 runs give wildly
   different speedups, the host is flaky and we bail.
3. `fingerprint_stable` — the fingerprint captured at the start of each
   run matches the baseline fingerprint. Catches mid-run frequency
   governor changes, CPU hotplug, kernel upgrades during a long run, etc.

The orchestrator defaults to `n=3`. If any of the three gates fail,
`artifact.determinism_ok = false` and the PR step is skipped — we surface
the partial report but we **do not** open a PR with flaky numbers.

---

## Flame-graph capture

Source: `crates/ods-lang-rust/src/flame.rs`.

Optional, best-effort. Strategy is tier-of-tools:

1. `cargo flamegraph --bench <name>` if the `cargo-flamegraph` subcommand
   is on PATH.
2. `perf record -F 997 -g` → `perf script` → `stackcollapse-perf` →
   `flamegraph.pl` if the perf suite and FlameGraph scripts are
   available.
3. `Ok(None)` — the run continues without a flame graph.

The SVG path is stored in `ProfileReport.flame_svg_path` and the PR
renderer embeds it in a collapsed `<details>` block. See
`docs/integrations.md` for how the SVG is uploaded alongside the PR body.

---

## End-to-end measurement flow

This is what happens between `Profile` and `Bench` in the Loop, end to end:

```
Orchestrator::run target T
│
├─ adapter.detect(repo)  →  Rust
├─ adapter.build(repo)   →  Build { workdir, toolchain }
│
├─ PRE phase ────────────────────────────────────────────────────
│    ├─ assert_determinism()  →  Locked | Soft
│    ├─ EnvFingerprint::capture()  →  fp_pre
│    ├─ adapter.profile(build, T)
│    │     ├─ /usr/bin/time -v cargo bench -- T   → wall
│    │     ├─ strace -c -f cargo bench -- T       → syscalls
│    │     └─ perf stat -e … cargo bench -- T     → counters
│    ├─ ProfileGate::validate(pre_profile)?
│    └─ adapter.run_bench(build, T)  →  pre_samples
│
│  (Planner + specialist race run here; winner's patch applied)
│
├─ POST phase ───────────────────────────────────────────────────
│    (same four steps on the patched worktree)
│
├─ stats::compare(pre_sample, post_sample)  →  SpeedupVerdict
├─ rerun(3, measure)  →  RerunReport
├─ ZeroDiffGate::evaluate(tests, fuzz, property, semver, verdict)
│     ├─ pass  →  render_pr_body + open PR
│     └─ fail  →  artifact.pr_withheld = true; partial report
│
└─ persist Run + events into .ods/runs.db
```

Every intermediate artefact — raw bench JSON, fingerprint, strace output,
perf counters, flame SVG, pre/post diff of the patch, gate report — is
written under `.ods/runs/<run-id>/` so `ods explain <run-id>` can
reconstitute the story without re-running anything.

---

## What's real vs stubbed today

| Component               | Status                                               |
|-------------------------|------------------------------------------------------|
| Subprocess profiler     | Real (time + strace + perf stat).                    |
| Criterion JSON ingest   | Real.                                                |
| Libtest bench parser    | Real.                                                |
| Bench scaffolder        | Real.                                                |
| Bootstrap CI stats      | Real (deterministic XorShift, 2000 iters, 99% CI).   |
| Tukey outlier filter    | Real.                                                |
| Env fingerprint         | Real (file-system only).                             |
| Determinism assertion   | Real.                                                |
| CPU pinning (taskset)   | Real (composes argv; caller executes).               |
| Rerun-N gate            | Real.                                                |
| Flame graph capture     | Real (best-effort, two fallbacks).                   |
| eBPF-based profiler     | **Not yet** — stage-2 swap-in behind `Profiler` trait. |
| `perf_event_open` direct | **Not yet** — deferred with eBPF.                   |
| macOS dtrace fallback   | **Not yet** — today macOS runs skip profiler fields. |

The subprocess path is enough for the zero-diff gate to do its job on
Linux CI runners. The eBPF swap-in is a known stage-2 item that drops in
behind the same `Profiler` trait with no caller changes.
