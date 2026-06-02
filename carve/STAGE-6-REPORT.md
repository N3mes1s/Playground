# carve — Stage 6: autonomous `harden` at scale (ripgrep)

`carve harden` runs the whole pipeline in **one command**, no manual per-crate
driving: vendor the transitive closure → detect which crates are actually
compiled for this target → slice every one → apply an economic gate
(`--min-reduction`) that reverts slices too small to be worth owning → time a
clean `--release` build before and after.

```
carve harden --manifest-path ripgrep/Cargo.toml --transitive --min-reduction 10
```

## Result on `BurntSushi/ripgrep` (43-crate closure, depth 7)

```
══════════ supply-chain hardening summary ══════════
  crates owned (sliced & kept): 16
  reverted (below 10% bar): 9    skipped (unsliceable): 0
  across the 16 owned crate(s):
      files        637 -> 464       -27.2%
      LOC       375603 -> 164310    -56.3%
      items      61815 -> 5166      -91.6%
      bytes   11418316 -> 5715177   -49.9%
      unsafe      1611 -> 1057      -34.4%
  clean --release build: 29.1s -> 29.5s  (-1.2%)
```

The economic gate behaves exactly as intended — keep the big wins, drop the
crates not worth owning:

| kept (≥10%) | reduction | reverted (<10%) | reduction |
|---|---|---|---|
| `encoding_rs` | **−81%** | `regex-automata` | −5% |
| `log` | −62% | `regex-syntax` | −0% |
| `crossbeam-deque` | −56% | `serde_core` | −8% |
| `crossbeam-utils` | −52% | `termcolor` | −7% |
| `libc` | −49% | `crossbeam-epoch` | −7% |
| `walkdir` | −47% | `bstr` | −0% |
| `serde` / `serde_json` | −43% | `encoding_rs_io` | −2% |
| `memchr` | −29% | `anyhow`, `cfg-if` | −1% |

ripgrep is a *regex* tool, so it uses nearly all of `regex-automata` /
`regex-syntax` → they revert to upstream. It barely touches `encoding_rs` (it
pulls in 137K LOC of character-encoding tables and uses ~a quarter) → carve
carves **81%** of it away. Every kept slice is verbatim, compiler-verified, and
the consumer still builds.

## Why the `--release` build is NOT faster (the honest finding)

Removing 56% of the source LOC barely moved the optimized build (29.1s → 29.5s,
i.e. noise). We profiled it (`cargo build --release --timings`); top units:

```
  15.8s  regex-automata 0.4.14     ← reverted (−5%): used heavily, kept upstream
   9.8s  regex-syntax 0.8.10       ← reverted (−0%)
   8.7s  ripgrep 15.1.0            ← the binary itself
   7.7s  aho-corasick 1.1.4        ← kept, but only −11%
   5.1s  encoding_rs 0.8.35        ← kept, −81% LOC … still 5.1s
```

Three compounding reasons:

1. **The compile-time-dominant crates are exactly the ones we keep upstream.**
   `regex-automata` (15.8s) + `regex-syntax` (9.8s) are ~30% of total unit-time,
   and both fell below the 10% bar because ripgrep uses ~all of them. You cannot
   cut compile cost out of code you actually use.
2. **The code we removed is compile-cheap.** `encoding_rs` shed 81% of its LOC
   but still costs 5.1s — what we deleted was ~110K lines of *static encoding
   data tables* and unused codecs: enormous LOC, near-zero codegen. `libc` −49%
   is `extern`/type/const declarations that emit no machine code at all.
   Release-build time is dominated by **LLVM optimizing the monomorphized code
   that is actually called**, which scales with *used* code, not source size.
3. **`rustc` already skips dead code.** Unused functions and un-instantiated
   generics are never monomorphized or optimized in a release build, so deleting
   them removes work the compiler was never doing.

### Takeaway

carve's value is **supply-chain security, not build speed**:

- **−56% LOC, −34% `unsafe`, −91% items** of trusted third-party code removed —
  a dramatically smaller attack surface, CVE-exposure footprint, and proof-read
  burden, all pulled into a tree you own and can diff on every upgrade.
- Optimized compile time is essentially unchanged, because build cost lives in
  the heavily-used crates you keep and in codegen of used code — neither of which
  dead-code removal touches. (A debug build, which is parse/typecheck-bound, would
  show a slightly larger but still modest improvement.)

If build-time reduction were the goal, the lever is different (fewer/leaner
*used* dependencies, less monomorphization), and carve's DFUG is exactly the tool
to find which heavy crates you use only a sliver of — e.g. dropping a dependency
entirely, not slicing it.
