# carve — Stage 2 + 3 proof (real project: BurntSushi/aho-corasick)

Reproduce with [`examples/aho-corasick-demo.sh`](examples/aho-corasick-demo.sh).
Target: [`BurntSushi/aho-corasick`](https://github.com/BurntSushi/aho-corasick)
(`v1.1.4`), its dependency [`memchr`](https://github.com/BurntSushi/memchr)
(`v2.8.1`). Host: Linux x86_64, Rust 1.94.

This proves the three claims end to end: **(1)** the Dependency Functional Usage
Graph, **(2)** vendoring + agent-slicing down to *only the code we use* while the
project still compiles and **no project source is changed**, and **(3)** an
update-impact verdict framed by what we actually use.

---

## 1. Dependency Functional Usage Graph — what aho-corasick uses from memchr

```
$ carve analyze --manifest-path aho-corasick/Cargo.toml

Dependency Functional Usage Graph — aho-corasick
  dependencies referenced: 2

  memchr v2.8.1  —  6 item(s), 12 ref(s)
        3×  memchr::memmem::Finder
        2×  memchr::memchr
        2×  memchr::memchr2
        2×  memchr::memchr3
        2×  memchr::memmem::Finder::new
        1×  memchr::memmem

  Declared but unreferenced (drop candidates):
      - log
```

aho-corasick calls exactly **6 items** from memchr. `log` is declared but unused
in the default build (correctly flagged for removal).

## 2. Vendor + slice to only what we need — no source changes

### 2a/2b. Vendor verbatim and wire the reversible patch

```
$ carve vendor-all --manifest-path aho-corasick/Cargo.toml --apply
  ✓ memchr v2.8.1  (60 files)
  added [patch.crates-io] entries

$ git -C aho-corasick diff --stat
 Cargo.toml | 3 +++
 1 file changed, 3 insertions(+)        # the ONLY change to the project

$ cargo build           # → build OK against vendored deps
```

The entire change to the real project is **3 lines in `Cargo.toml`** (the
`[patch.crates-io]` entry) plus the added `vendor/` tree. Zero source edits.

### 2c. The agent slices memchr down to only the needed modules

```
$ carve slice memchr --manifest-path aho-corasick/Cargo.toml

  discovered removable modules  candidates=44
  carve_attempt{module=src/arch}:    kept   — removing it breaks compile (reverted)
  carve_attempt{module=src/arch/aarch64}: carved away — consumer still compiles
  carve_attempt{module=src/arch/wasm32}:  carved away — consumer still compiles
  carve_attempt{module=src/arch/all/shiftor}: carved away
  carve_attempt{module=src/tests}:    carved away

  carved away 4 module(s):
      - src/arch/aarch64        (ARM SIMD — dead on x86_64)
      - src/arch/wasm32         (WASM SIMD — dead on x86_64)
      - src/arch/all/shiftor    (unused search algorithm)
      - src/tests               (upstream test suite)

  files: 45 -> 26   LOC: 15799 -> 11602  (26.6% reduction)
  kept (needed to compile): 25 module(s)
  consumer build verified after slicing: YES

$ cargo build              # → build OK against SLICED deps
$ carve verify             # → OK   memchr v2.8.1 (41 files match ledger)
```

The agent ran `cargo check` against the **real consumer** after every candidate
cut (44 attempts, fully traced via `--log-json`). It kept only what compiles:
the x86_64 / generic / `all` backends and `memmem`. It carved away the ARM and
WASM SIMD backends (cfg-dead on this target), an unused algorithm, and the test
suite. Every kept byte is still byte-identical to upstream (provenance verified).

> Honesty note: this is **module-level**, target-specialized slicing. memchr's
> public surface (`memmem`, the x86 backends) is genuinely needed by
> aho-corasick, so it stays. The compiler — not a heuristic — decides what is
> removable, which is why the result always compiles and never invents code.
> Removing the ARM/WASM backends pins the vendored copy to x86_64; that's the
> intended trade for a smaller attack surface on your deployment target.

## 3. What a dependency update touching us means

```
$ carve impact memchr --to 2.6.0 --manifest-path aho-corasick/Cargo.toml

  upstream changed 20 file(s) total:
      5 outside your slice  → cannot touch you
      15 inside your slice   → proof-read surface
  ...
      src/memmem/mod.rs  ⚠ used API   (Finder, find, find_iter, …)
      src/memchr.rs      ⚠ used API   (memchr, memchr2, memchr3, …)

  VERDICT: PROOF-READ REQUIRED — update changes items you CALL:
           Finder, memchr, memchr2, memchr3, memmem
```

The same analysis for a tiny adjacent bump shows the discriminating power:

| Update            | upstream changed | outside slice (ignored) | touches used API | verdict |
|-------------------|------------------|--------------------------|------------------|---------|
| 2.8.1 → 2.6.0     | 20 files         | 5                        | yes (5 items)    | proof-read |
| 2.8.1 → 2.7.4     | 12 files         | 2                        | yes (`Finder`)   | proof-read |
| 2.8.1 → 2.8.0     | 5 files          | 0                        | yes (`Finder`)   | proof-read |

Every memchr release in this range edits `memmem` (which aho-corasick calls), so
they all demand a proof-read — and carve tells you *exactly which used item*
changed and *which changed files you can ignore* because they're outside your
slice. A release that only touched `arch/aarch64` would land entirely in
"cannot touch you" and read **SAFE** — bump freely.

---

## What this demonstrates

- **DFUG is real:** extracted from a real project, pinpointing 6 used items.
- **The vendored part is the part we need:** agent-driven, compiler-verified
  slicing removed 26.6% of memchr while the real consumer keeps compiling.
- **Updates are scoped to us:** impact analysis converts a 20-file upstream diff
  into a 5-item proof-read surface (or "SAFE" when nothing we use changed).
- **Reversible:** `carve restore memchr` puts the project back on the upstream
  dependency and it rebuilds — proven at the end of the demo script.
