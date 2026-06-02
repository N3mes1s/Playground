# carve — Stage 5: item-level slicing, native/sys fix, and attack-surface %

Two capabilities completed, plus the metric that ties the whole project together.

## 1. Single-item slicing — made cheap (compiler-guided convergence)

`carve slice <crate> --items` removes individual top-level items
(`fn`/`struct`/`enum`/`impl`/…) verbatim, keeping only what still compiles
against the real consumer. The naive way is one `cargo check` per item —
hundreds of builds. carve does it in **~O(reference-depth)** instead:

1. **Remove everything removable at once**, then run one `cargo check`.
2. The compiler's `cannot find \`X\`` errors name exactly what the live code
   still needs. **Restore those items and re-check.** Iterate to convergence.
3. A short, budget-bounded greedy **refinement** mops up redundant copies the
   name-based restore over-kept (e.g. a `memchr_raw` per CPU backend).

```
$ carve slice memchr --manifest-path aho-corasick/Cargo.toml --items   # budget 80

Item-level slicing (budget 80 verifications)…
  fast pass: removed 10 item(s) in just 6 check(s) (compiler-guided convergence)
  total: removed 21/250 top-level item(s) via 80 verification(s)
  LOC after items: 11602 -> 11173
  consumer build verified after item-slicing: YES
```

The convergence trace (5 rounds): remove all 202 removable items → the compiler
restores 57, then 60, 35, 18, 22, and it compiles. The expensive old sweep needed
300+ checks for a comparable result and didn't even finish one pass; the new fast
pass delivers most of the win in **6 checks**, and `--budget` controls how much
optional refinement to spend after that (set it low for a quick slice, high for
maximal removal). Items carved are exactly what aho-corasick never calls — the
unused SIMD iterator impls `impl OneIter/TwoIter/ThreeIter`, unused public
functions like `find_iter`/`rfind_iter`, etc. Every removal is byte-verbatim and
verified; nothing is invented.

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
