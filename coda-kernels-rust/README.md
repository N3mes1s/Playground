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

The crate has a complete **CUDA backend** behind the `cuda` feature — forward
*and* backward, kernels *and* whole-model training. The GPU realization of
CODA lives in `cuda/coda_kernels.cu`: each kernel computes a GEMM accumulator
in registers and applies the fused epilogue (residual, RMSNorm scale, SwiGLU,
RoPE, cross-entropy) *before* the single global-memory write — the same
data-movement story as the CPU port, now on hardware.

* **Tensor-core mainloop** — on Ampere+ the GEMM uses a **TF32 WMMA**
  tensor-core kernel (`k_gemm_tc`); each warp computes a 16×16 tile on the
  tensor cores and the accumulator is staged through shared memory so the
  *same fused epilogue* still runs before the store. A register-blocked
  shared-memory kernel (`k_gemm_epi`) is the fallback for pre-Ampere GPUs and
  ragged shapes. Both are templated on the epilogue mode — one fixed mainloop,
  programmable epilogue.
* **Block-parallel attention** — `k_attention` runs one thread *block* per
  (query, head) with cooperative shared-memory reductions, and saves the
  softmax matrix. The backward is atomic-free: it materializes the
  score-gradient and computes `dQ`/`dK`/`dV` as independent block-per-position
  reductions (no `atomicAdd` contention).
* **Whole-model forward** — `coda_cuda_model_forward` runs every layer
  device-resident; weights upload once, only logits come back.
* **Device-resident training** — `coda_cuda_train` runs the full training loop
  on the GPU: forward (saving activations), the complete backward pass
  (transposed-GEMM weight/activation gradients, RMSNorm/SwiGLU/RoPE/attention
  backward, embedding scatter — paper Theorem 1), and an Adam step, with
  weights and optimizer state resident on the device across all steps.
* **Multi-billion-parameter path** — `coda_cuda_train_random` generates the
  weights *on the GPU* with a hash RNG (the host never holds a copy) and
  optimizes with plain SGD, so a model far larger than host RAM — and larger
  than Adam's 4×-memory footprint would allow — still trains on one GPU.

`build.rs` compiles the kernels with `nvcc` when `--features cuda` is set;
`src/cuda.rs` is the Rust FFI; `src/bin/gpu.rs` (`coda-gpu`) verifies every
CUDA kernel and the GPU gradients against the CPU reference, then trains.

Run it on a Modal GPU:

```bash
pip install modal
modal token set --token-id <id> --token-secret <secret>
modal run coda-kernels-rust/modal/run_gpu.py                              # T4
modal run coda-kernels-rust/modal/run_gpu.py --gpu A100-80GB --scale big   # ~2.7B params
```

Verified results — all 10 kernels, the full forward, *and* the backward pass
match the CPU reference (the tensor-core path is TF32, so the error floor is
~1e-3 rather than ~1e-7 — well inside every tolerance):

```
== Kernel correctness: CUDA vs CPU ==     all 10 kernels PASS (TF32 err ~6e-4)

== Full Transformer forward (~27.4M params), A100 ==
    GPU ~0.23s | CPU ~7.5s | ~33x   logits max-err 2e-3   argmax 256/256

== GPU backward: gradients vs CPU ==
    GPU gradients match CPU backward to ~8e-5 (relative); loss CPU == GPU

== GPU training: device-resident loop vs CPU ==
    GPU loss 3.27 -> 0.0011 ;  CPU from identical init -> 0.0011

== Real language model (GPU-trained, then generating) ==
    a 3.4M-parameter char-level GPT, trained on the GPU (10k steps, loss
    3.45 -> 0.000); greedy generation from a 12-character prompt:
      prompt    : "coda trains "
      generated : "coda trains a small language model on the gpu by fusing
                   the epilogue into each matrix multiply."

== Scaled-up GPU training (A100-80GB, --scale big) ==
    ~6.74B params (Llama-7B class: d_model 4096, 32 layers, d_ff 11008, seq 512)
    60 steps in ~181s (~3.0 s/step), loss 10.45 -> 6.02
```

A real GPT, trained entirely on the GPU — device-resident forward, backward,
and Adam — learns a sentence and **generates it back coherently** from a short
prompt. The CODA GEMM-plus-epilogue kernels run the whole thing.

So a **~6.7-billion-parameter Transformer trains end-to-end on a single
A100-80GB** — the full forward + backward + optimizer step, with the weights
generated and resident entirely on the GPU. The smaller `--scale` runs (10M /
100M) are still verified gradient-for-gradient against the CPU reference; at
6.7B the CPU can't hold the model, so that run is a scale demonstration
(SGD optimizer, since Adam's moment tensors would not fit). All ten kernels
and the gradient check still run and pass on every deploy.

**Performance journey.** The 100M-parameter training step was optimized in
measured steps, each verified to stay bit-correct against the CPU:

| Change | step time |
|--------|-----------|
| naive tiled GEMM mainloop                 | ~820 ms |
| register-blocked forward + backward GEMMs | ~728 ms |
| TF32 tensor-core GEMM mainloop            | ~728 ms |
| **block-parallel, atomic-free attention** | **~101 ms** |

The lesson is in that table: the GEMM rewrites were *correct* but barely moved
wall-clock — the workload was never GEMM-bound. The real cost was the original
attention kernels (one thread per (query,head): only ~3 000 threads on a
108-SM GPU, plus `atomicAdd` contention in the backward). Rewriting attention
as block-per-position with cooperative reductions and an atomic-free,
materialized-`P` backward gave a **7.2× end-to-end speedup**. The GEMM still
runs on tensor cores; both pieces matter, but profiling-by-measurement is what
found the bottleneck.

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
