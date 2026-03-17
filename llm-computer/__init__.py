"""
LLM Computer: Executing programs inside a transformer.

Based on Percepta's "Can LLMs Be Computers?" (March 2026).
https://www.percepta.ai/blog/can-llms-be-computers

Architecture:
    - VanillaTransformer with 2D attention heads (d_model=36, n_heads=18)
    - WASM interpreter compiled into transformer weights (no training)
    - HullKVCache for O(log n) attention via 2D convex hull queries
    - Execution trace generation at 30k+ tok/s on CPU

Components:
    model.py            - VanillaTransformer architecture
    weight_compiler.py  - Compiles WASM programs into transformer weights
    hull_kv_cache.py    - HullKVCache with 2D convex hull
    wasm_vm.py          - WebAssembly virtual machine
    compiler.py         - Trace tokenization (VM trace ↔ token sequences)
    executor.py         - Execution engine (VM and transformer modes)
    sandbox.py          - Transformer's internal compute substrate (pywasm)
    demo.py             - Interactive demos
"""

from .model import VanillaTransformer
from .hull_kv_cache import HullKVCache, StandardKVCache, ConvexHull2D
from .wasm_vm import WasmVM, Op, Instruction
from .compiler import TraceCompiler, TraceVocab
from .weight_compiler import compile_program
from .executor import Executor, StreamingExecutor, ExecutionResult
