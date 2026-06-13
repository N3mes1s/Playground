//! Code2LoRA in Rust — hypernetwork-generated LoRA adapters from a code
//! repository (arXiv:2606.06492, Code2LoRA-Static).
//!
//! Pipeline: `embedder` encodes a repo into R^2048 -> `hypernet` maps it to a
//! LoRA adapter in one forward pass -> `lora` exports a PEFT adapter for the
//! `model` described base LLM.

pub mod embedder;
pub mod evo;
pub mod hypernet;
pub mod lora;
pub mod model;
pub mod tensor;
pub mod train;
