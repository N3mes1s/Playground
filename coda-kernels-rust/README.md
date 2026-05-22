# coda-kernels-rust

A faithful, **CPU-only Rust port of CODA** — *"Rewriting Transformer Blocks as
GEMM-Epilogue Programs"* (Guo, Zhang, Menon, Guessous, Thakkar, Kim, Dao;
[arXiv:2605.19269](https://arxiv.org/abs/2605.19269), reference implementation
[HanGuo97/coda-kernels](https://github.com/HanGuo97/coda-kernels)).

The original project is CUDA/CuTeDSL targeting NVIDIA Hopper H100 GPUs. This
port keeps CODA's **abstraction and algebra exactly** and re-grounds the
hardware story on a CPU so the ideas can be run, tested, and inspected without
a GPU. It is the proof-of-concept stage before scaling the same design up on a
real GPU via Modal.com.

## What CODA is

Transformer training spends a non-trivial fraction of its time on *memory-bound*
operators — normalization, activations, residual updates, reductions — that
shuttle large intermediate tensors through global memory while doing little
arithmetic. CODA's insight: many of these operators can be **algebraically
reparameterized to run inside the epilogue of a GEMM**, while the output tile is
still on-chip, before it is ever written back to memory. The GEMM mainloop is
held fixed and highly optimized; only the epilogue is programmable.

```
   x ─▶[ GEMM mainloop ]─▶ accumulator tile (on-chip)
                                  │
                                  ▼
                     [ epilogue visitor tree ]   ◀── residual, RMSNorm,
                                  │                   SwiGLU, RoPE, cross-entropy
                                  ▼
                            global memory  (one write, no round-trips)
```

## What this port implements

Everything in the paper's non-attention forward **and** backward pass:

### The abstraction (`src/gemm.rs`, `src/epilogue.rs`)

* A fixed tiled **GEMM mainloop** that produces one on-chip accumulator
  `Frag` per output tile and exposes the epilogue hook points of the paper's
  template (Listing 1): `consumer_init / begin / visit / end`.
* The **Epilogue Visitor Tree**: an `EpilogueVisitor` trait, an `EvtList`
  combinator, and the paper's five primitive classes —
  1. elementwise/pairwise maps (`EvtResidual`, `EvtRowScale`, `EvtSwiGLUStore`,
     `EvtRoPEStore`, `EvtRowVecMulStore`),
  2. vector (rank-1) loads/stores,
  3. tile (rank-2) loads/stores (`EvtStore`),
  4. tile reductions (`EvtColBlockReduceStore`, `EvtRowReduceStore`),
  5. stateful transforms (`EvtCrossEntropyStore` — online log-sum-exp).

### All 10 kernels (`src/kernels.rs`, paper §C.1)

| # | Function | Computation |
|---|----------|-------------|
| 1 | `gemm_rope` | `D = AB`, `O = RoPE(D)` |
| 2 | `gemm_swiglu` | `D = AB`, `O = silu(G)⊙U` |
| 3 | `gemm_partial_ce` | `Z = AB`, target logit + log-sum-exp partials |
| 4 | `gemm_residual_partial_rms` | `D = AB+C`, partial RMS, `O = D⊙γ` |
| 5 | `gemm_rmsnorm` | `D = AB`, `O = D⊙r` (delayed-scale) |
| 6 | `gemm_rmsnorm_swiglu` | `D' = (AB)⊙r`, `O = silu(G)⊙U` |
| 7 | `gemm_rmsnorm_rope` | `D' = (AB)⊙r`, `O = RoPE(D')` |
| 8 | `gemm_rmsnorm_partial_ce` | `Z = (AB)⊙r`, cross-entropy partials |
| 9 | `gemm_residual_rmsnorm_bwd` | RMSNorm backward (local rule) |
| 10 | `gemm_swiglu_bwd` | SwiGLU backward |

Plus the **auxiliary reductions** (`src/reduce.rs`) that combine tile partials
into the row-wise RMS factor `r` and the cross-entropy log-sum-exp.

### A tiny Transformer (`src/model.rs`, `src/train.rs`)

A LLaMA-style decoder (pre-norm RMSNorm, RoPE, causal attention, SwiGLU MLP).
Its entire non-attention forward pass is the paper's **GEMM-Residual-RMSNorm-
GEMM** chain: each Kernel 4 emits the *next* sublayer's normalized input as a
side output, and the row-wise factor `r` is applied in the *next* GEMM's
epilogue (the delayed-scale trick — `r` commutes with the following GEMM). The
backward pass follows the paper's Theorem 1: every fused forward block has a
backward block of the same `GEMM → tile-local transform → GEMM` shape.

## Running it

```bash
cargo run --release      # the full demonstration
cargo test  --release    # the integration test suite
```

The demo runs five stages, all of which must pass:

1. **Kernel correctness** — all 10 kernels vs. unfused reference math.
2. **Forward equivalence** — the fused CODA forward equals the naive
   operator-sequence forward (max error ~1e-6).
3. **DRAM traffic** — the fused path streams 17–22% fewer bytes through global
   memory (the saving grows with sequence length); it never materializes the
   residual stream or the normalized activations as standalone tensors.
4. **Gradient check** — analytic backward vs. finite differences.
5. **A working model** — trains to memorize a sentence (loss 3.07 → 0.0003 in
   ~8s on CPU) and then *exactly reproduces it* by greedy generation.

```
seq  2048 : naive    45534 KiB  |  CODA    35462 KiB  |  saved 22.1%
...
prompt    : "coda f"
generated : "coda fuses transformer epilogues into a gemm kernel."
--> generation exactly reproduces the training corpus.
```

## Honest scope notes

* CODA's *latency* win is GPU-specific (WGMMA pipelines, TMA, hiding epilogue
  work in another tile's mainloop). On a CPU we instead measure the
  **algorithmic data-movement reduction** — bytes through "global memory" — via
  the instrumented counters in `src/tensor.rs`. That reduction is real and
  faithful to the paper's reparameterization; the wall-clock win is what the
  GPU port is for.
* Attention is deliberately *outside* CODA's scope (paper §5) and is a plain
  implementation here, identical in both forward paths.
* GEMMs are plain triple loops — correctness over speed; the point is the
  epilogue abstraction, not a fast CPU GEMM.

## GPU backend (CUDA, via Modal.com)

The crate has a real **CUDA backend** behind the `cuda` feature. The GPU
realization of CODA lives in `cuda/coda_kernels.cu`: each kernel computes a
GEMM accumulator in registers and applies the fused epilogue (residual,
RMSNorm scale, SwiGLU, RoPE, cross-entropy) *before* the single global-memory
write — the same data-movement story as the CPU port, now on hardware. The
GEMM mainloop is a simple one-thread-per-output-element loop (correctness over
peak FLOPs; a tiled / WGMMA mainloop can be slotted in later without touching
the epilogue structure).

`build.rs` compiles the kernels with `nvcc` when `--features cuda` is set;
`src/cuda.rs` is the Rust FFI; `src/bin/gpu.rs` (`coda-gpu`) verifies every
CUDA kernel against the CPU reference and benchmarks GPU vs CPU.

Run it on a Modal GPU:

```bash
pip install modal
modal token set --token-id <id> --token-secret <secret>
modal run coda-kernels-rust/modal/run_gpu.py
```

The whole Transformer forward also runs on the GPU as a single device-resident
pass (`coda_cuda_model_forward` / `cuda::model_forward`): weights are uploaded
once, every activation stays on the device across all layers, and only the
logits come back.

Verified result on an NVIDIA T4 — all 10 kernels *and* the full model are
bit-faithful to the CPU reference:

```
== Kernel correctness: CUDA vs CPU reference ==
    [PASS] gemm_residual_partial_rms (D)   max-err = 3.6e-7   ... all 10 PASS

== Benchmark: gemm_residual_partial_rms (Kernel 4) ==
     768^3 : CPU 0.50s (1.8 GFLOP/s) | GPU 0.012s (73 GFLOP/s) | 40x
    2048^3 : GPU 0.146s (118 GFLOP/s) [CPU too slow]

== Full Transformer forward on GPU: CUDA vs CPU ==
    [PASS] model_forward (tiny): CUDA vs CPU logits  max-err = 8.3e-7
           next-token argmax agreement: 48/48

== Scaled-up model: full forward, GPU vs CPU ==
    d_model=512, layers=6, heads=8, d_ff=1376, vocab=8192, seq=256 (~27.4M params)
    GPU forward 0.32s | CPU forward 7.34s | 23x speedup
    next-token argmax agreement: 256/256   logits max-err = 3.1e-6
```

**Next step:** the GEMM mainloop is still a naive one-thread-per-element loop;
swapping in a tiled / tensor-core mainloop (the part CODA keeps fixed) and
training on the GPU are the remaining optimizations. Larger models scale on a
dedicated A100/H100 Modal GPU by editing the config in `src/bin/gpu.rs`.

## File map

```
src/tensor.rs     Mat type + DRAM-traffic instrumentation
src/gemm.rs       fixed tiled GEMM mainloop + epilogue hook points
src/epilogue.rs   EpilogueVisitor trait, EvtList, the 5 primitive classes
src/kernels.rs    the 10 GEMM-plus-epilogue kernels
src/reduce.rs     auxiliary reductions over tile partials
src/reference.rs  naive unfused operators (correctness + traffic baseline)
src/model.rs      tiny LLaMA-style Transformer on CODA kernels
src/train.rs      backward pass (Theorem 1), Adam, training, gradient check
src/main.rs       the CPU demonstration binary
src/cuda.rs       Rust FFI to the CUDA backend            (feature `cuda`)
src/bin/gpu.rs    GPU verification + benchmark binary     (feature `cuda`)
cuda/             CUDA kernels (coda_kernels.cu)
build.rs          compiles the CUDA kernels via nvcc
modal/run_gpu.py  Modal app: build + run the GPU backend
tests/            integration tests
```
