//! # coda
//!
//! A faithful CPU implementation of **CODA** (Guo et al., arXiv:2605.19269),
//! *"Rewriting Transformer Blocks as GEMM-Epilogue Programs"*.
//!
//! CODA's thesis: the memory-bound operators that surround Transformer GEMMs
//! (normalization, residual updates, activations, reductions, cross-entropy)
//! can be *algebraically reparameterized* to run inside the **epilogue** of a
//! GEMM, while the output tile is still on-chip, before it is written back to
//! global memory. This removes redundant round-trips to global memory.
//!
//! This crate is the paper's abstraction and the ten GEMM-plus-epilogue
//! kernels (§C.1), in pure Rust, with no model or training code. It is the
//! piece that is faithful to the paper. The LLaMA-architecture model, the
//! training driver, and the CUDA backend that runs on a real GPU all live in
//! the sibling `coda-llama` crate, which consumes this one as its primitives.
//!
//! Module map:
//! * [`tensor`]    - the `Mat` type and DRAM-traffic instrumentation.
//! * [`gemm`]      - the fixed tiled GEMM mainloop with epilogue hook points.
//! * [`epilogue`]  - the Epilogue Visitor Tree: trait + composable primitives.
//! * [`kernels`]   - the 10 GEMM-plus-epilogue kernels from the paper.
//! * [`reduce`]    - lightweight auxiliary reductions over tile partials.
//! * [`reference`] - naive unfused operators (correctness + traffic baseline).

pub mod tensor;
pub mod gemm;
pub mod epilogue;
pub mod kernels;
pub mod reduce;
pub mod reference;
