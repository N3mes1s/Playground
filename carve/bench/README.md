# carve benchmark

Measures two things the reachability-SCA market is bought and sold on:

1. **Noise reduction** — what fraction of `cargo audit` findings carve clears
   (`not_affected`) or down-prioritizes (`needs review`).
2. **False clears** — the one error a fail-safe triager must never make:
   clearing a finding that is actually reachable. The verifier re-derives ground
   truth from cargo's own resolve graph, independently of carve, and audits every
   `not_affected` verdict. The target is **0**.

## Run

```bash
cargo build --release                 # build carve
cargo install cargo-audit             # the version-match baseline
./bench/run.sh                        # clone corpus, audit, triage, save JSON -> bench/data/
python3 ./bench/verify.py             # join, check false clears, write REPORT-BENCHMARK.md
```

`run.sh` clones the RustSec advisory DB to `/tmp/advisory-db` (override with
`ADVISORY_DB`). Triage targets `linux/x86_64` by default; override the verifier
with `BENCH_TARGET_OS` / `BENCH_TARGET_ARCH`.

`verify.py` exits non-zero if it finds any false clear.

## Why the oracle is independent

carve decides `not_affected` from its own Rust pass over `cargo metadata`. The
verifier re-derives the same facts — is the crate in the resolved package set?
is it reachable via normal-only edges? does the advisory's `os`/`arch` exclude
the target? — in a separate Python implementation over the raw `cargo metadata`
JSON. If carve clears something the oracle can't justify, that is a real bug and
the benchmark fails. It is a cross-implementation check against cargo's
authoritative resolve graph, not an exploitability oracle.
