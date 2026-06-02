# carve — Stage 5: item-level slicing, native/sys fix, and attack-surface %

Two capabilities completed, plus the metric that ties the whole project together.

## 1. Single-item slicing (finer than whole modules)

`carve slice <crate> --items` runs the same dynamic, compiler-gated loop as
module slicing, but at the granularity of individual top-level items
(`fn`/`struct`/`enum`/`impl`/…). For each item it deletes the item verbatim, runs
`cargo check` against the real consumer, and keeps the cut only if it still
compiles — in passes to a fixpoint, bounded by a verification `--budget`.

```
$ carve slice memchr --manifest-path aho-corasick/Cargo.toml --items --budget 300

  carved away 4 module(s): src/arch/aarch64, src/arch/wasm32, src/arch/all/shiftor, src/tests
  files: 45 -> 26   LOC: 15799 -> 11602  (module-level: 26.6%)

Item-level slicing (budget 300 verifications)…
  removed 41 top-level item(s) via 300 verification(s)
  LOC after items: 11602 -> 11145
  consumer build verified after item-slicing: YES
```

Items the agent carved are exactly the ones aho-corasick never calls — e.g. the
unused SIMD iterator impls `impl OneIter / TwoIter / ThreeIter` in the AVX2 and
SSE2 backends, and unused public functions. Each removal is byte-verbatim and
verified; nothing is invented. (Item-level is more expensive than module-level —
one `cargo check` per item — so it is budget-bounded and best run after the
cheap module pass.)

## 2. Native/sys crates: the faithful path

Native `*-sys` crates compile bundled C via shipped autotools scripts. The
vendored `tikv-jemalloc-sys` failed to build even though it was byte-identical —
root cause: **file permissions**. Its `configure`, `autogen.sh`, `install-sh`
etc. are mode `755`; carve's copy wrote them `644`, so `build.rs` ran a
non-executable `./configure`, no config header was generated, and the C compile
broke.

Fix: **preserve the original mode bits when transcribing.** Now:

```
$ find fd/vendor -name configure -path '*jemalloc-sys*' -printf '%m %p\n'
755 .../tikv-jemalloc-sys-.../configure          # executable bit survives

$ cargo build   # Compiling tikv-jemalloc-sys (…/vendor/…)  → Finished
```

The full `sharkdp/fd` closure — **75 crates including the native jemalloc-sys** —
now vendors and rebuilds from local source. Only genuinely duplicated crates
(`bitflags`, `nix`, at two versions each) stay on the registry, a Cargo
`[patch]` limitation.

## 3. The headline metric: attack-surface reduction (%)

Every slice now reports how much attack surface carving removed, across several
dimensions — including the security-critical count of `unsafe` blocks:

```
  ── attack surface reduction (memchr) ──
      files         45 → 26       -42.2%
      LOC        15799 → 11145    -29.5%
      items        363 → 209      -42.4%
      bytes     565917 → 402552   -28.9%
      unsafe       333 → 221      -33.6%
      ► attack surface cut by ~29% (LOC), 34% of `unsafe` blocks removed
```

For a dependency we use 6 functions from, carve removed ~42% of the files and
items and a third of the `unsafe` surface — verbatim, reversible, and verified to
still compile the real consumer. That percentage *is* the supply-chain payoff:
less code we ship, fewer CVEs that can apply to us, a smaller proof-read surface
on every upgrade.
