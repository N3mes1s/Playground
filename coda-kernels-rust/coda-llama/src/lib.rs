//! # coda-llama
//!
//! A LLaMA-architecture Transformer (model + training + GPU backend) built on
//! the [`coda`] crate's GEMM-plus-epilogue kernels. This is the consumer side:
//! the actual paper-faithful CODA primitives live in [`coda`]; everything in
//! this crate is the model definition, the training driver, the CUDA backend
//! (forward + backward + Adam + KV-cached inference + batched decode), and the
//! binaries that exercise them.
//!
//! Module map:
//! * [`model`] - LLaMA-style Transformer built on CODA kernels.
//! * [`train`] - hand-written backward pass + Adam, used to train the model.
//! * `cuda`    - GPU backend (CUDA), present only with `--features cuda`.

pub mod model;
pub mod train;

/// GPU backend (CUDA). Present only when built with `--features cuda`; see
/// `cuda/coda_kernels.cu` and the Modal deployment in `modal/`.
#[cfg(feature = "cuda")]
pub mod cuda;
