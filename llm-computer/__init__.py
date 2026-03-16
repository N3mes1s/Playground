"""
LLM Computer: Executing programs inside a transformer.

Based on Percepta's "Can LLMs Be Computers?" (March 2026).
https://www.percepta.ai/blog/can-llms-be-computers

Architecture:
    - VanillaTransformer with 2D attention heads (d_model=36, n_heads=18)
    - WASM interpreter compiled into transformer weights
    - HullKVCache for O(log n) attention via 2D convex hull queries
    - Execution trace generation at 30k+ tok/s on CPU

Components:
    model.py        - VanillaTransformer architecture
    hull_kv_cache.py - HullKVCache with 2D convex hull
    wasm_vm.py      - Simplified WebAssembly virtual machine
    compiler.py     - Weight compiler (WASM interpreter -> transformer weights)
    executor.py     - Execution engine
    demo.py         - Interactive demos
"""

from .model import VanillaTransformer
from .hull_kv_cache import HullKVCache, StandardKVCache, ConvexHull2D
from .wasm_vm import WasmVM, Op, Instruction
from .compiler import WeightCompiler, TraceCompiler, TraceVocab
from .executor import Executor, StreamingExecutor, ExecutionResult
