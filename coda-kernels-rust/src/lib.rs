//! # CODA-rs
//!
//! A faithful, CPU-only Rust port of **CODA** (Guo et al., arXiv:2605.19269),
//! *"Rewriting Transformer Blocks as GEMM-Epilogue Programs"*.
//!
//! CODA's thesis: the memory-bound operators that surround Transformer GEMMs
//! (normalization, residual updates, activations, reductions, cross-entropy)
//! can be *algebraically reparameterized* to run inside the **epilogue** of a
//! GEMM, while the output tile is still on-chip, before it is written back to
//! global memory. This removes redundant round-trips to global memory.
//!
//! The original project targets NVIDIA Hopper GPUs via CUTLASS CuTeDSL. This
//! port keeps the *abstraction* and *algebra* exactly, and replaces the
//! hardware story with a CPU model: "global memory" is the heap, "on-chip"
//! is the register-resident accumulator tile, and the win is measured as
//! fewer bytes streamed through DRAM (see [`tensor`] traffic counters).
//!
//! Module map:
//! * [`tensor`]   - the `Mat` type and DRAM-traffic instrumentation.
//! * [`gemm`]     - the fixed tiled GEMM mainloop with epilogue hook points.
//! * [`epilogue`] - the Epilogue Visitor Tree: trait + composable primitives.
//! * [`kernels`]  - the 10 GEMM-plus-epilogue kernels from the paper.
//! * [`reduce`]   - lightweight auxiliary reductions over tile partials.
//! * [`reference`]- naive unfused operators (correctness + traffic baseline).
//! * [`model`]    - a tiny LLaMA-style Transformer built on CODA kernels.
//! * [`train`]    - hand-written backward pass + Adam, used to train the model.

pub mod tensor;
pub mod gemm;
pub mod epilogue;
pub mod kernels;
pub mod reduce;
pub mod reference;
pub mod model;
pub mod train;

/// GPU backend (CUDA). Present only when built with `--features cuda`; see
/// `cuda/coda_kernels.cu` and the Modal deployment in `modal/`.
#[cfg(feature = "cuda")]
pub mod cuda;
