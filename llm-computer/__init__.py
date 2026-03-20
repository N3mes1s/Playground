"""
LLM Computer: A WebAssembly interpreter compiled into transformer weights.

Based on Percepta's "Can LLMs Be Computers?" (March 2026).
https://www.percepta.ai/blog/can-llms-be-computers

The transformer IS the computer. Programs are encoded as input tokens.
The model generates execution traces step by step — every value computed
in the forward pass.

Core components:
    autoregressive_interpreter.py  - Hand-crafted weight setup + inference
    model.py                       - VanillaTransformer architecture
    wasm_vm.py                     - Reference WASM VM
    mini_c.py                      - C-to-WASM compiler (DIV/REM decomposition)
    compiler.py                    - Trace tokenization (TraceVocab)
    train.py                       - Training pipeline (research)
    rust_engine/                   - Rust inference engine (O(log n) attention)
"""

from .model import VanillaTransformer
from .wasm_vm import WasmVM, Op, Instruction
from .compiler import TraceCompiler, TraceVocab
