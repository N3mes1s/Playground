# carve — Stage 5: item-level slicing, native/sys fix, and attack-surface %

Two capabilities completed, plus the metric that ties the whole project together.

## 1. Single-item slicing — made cheap (precise compiler-guided convergence)

`carve slice <crate> --items` removes individual top-level items
(`fn`/`struct`/`enum`/`impl`/…) verbatim, keeping only what still compiles
against the real consumer. The naive way is one `cargo check` per item —
hundreds of builds. carve does it in **~O(reference-depth)** instead:

1. **Remove every removable item at once**, then run one `cargo check`.
2. The compiler's `cannot find \`X\`` errors name exactly what the live code
   still needs — and *where* (the module in `... in module \`crate::a::b\``,
   the path in `unresolved import \`crate::a::b::C\``, or the error's own source
   file). **Restore only the definition in the module the lookup pointed at**
   (longest module-prefix match), so a `memchr_raw` that exists in several CPU
   backends doesn't drag them all back. Re-check; iterate to convergence.

```
$ carve slice memchr --manifest-path aho-corasick/Cargo.toml --items   # default

Item-level slicing…
  fast pass: removed 10 item(s) in just 13 check(s) (compiler-guided convergence)
  total: removed 10/250 top-level item(s) via 13 verification(s)
  (convergence-only; pass --budget N to squeeze the impl/duplicate tail)
  ► attack surface cut by ~28% (LOC), 29% of `unsafe` blocks removed
```

The trace shows ~12 rounds restoring the live closure precisely, then it
compiles — **13 checks total**, versus 300+ for the old per-item sweep (which
didn't even finish one pass). That is the cheap default.

Reaching the *absolute* maximal set squeezes one more category — `impl` blocks,
which the compiler only reveals as needed when a method is actually called, so
they are irreducibly per-item. That tail is **opt-in** via `--budget N` (one
`cargo check` per candidate):

```
$ carve slice memchr --items --budget 200
  fast pass: removed 10 item(s) in just 13 check(s)
  total: removed 28/250 item(s) via 171 verification(s)
  ► attack surface cut by ~30% (LOC), 35% of `unsafe` blocks removed
```

Items carved are exactly what aho-corasick never calls — unused public functions
like `find_iter`/`rfind_iter` and the unused SIMD iterator impls
`impl OneIter/TwoIter/ThreeIter`. Every removal is byte-verbatim and verified;
nothing is invented.

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
