# LLM-as-Computer: WASM Interpreter in Transformer Weights

A WebAssembly interpreter that runs entirely inside a vanilla transformer's forward pass. Every value is computed by attention heads and feed-forward networks — no external tools, no VM at inference time.

Based on [Percepta's "Can LLMs Be Computers?"](https://percepta.ai/blog/can-llms-be-computers)

## How It Works

Programs are encoded as input tokens. The model generates an execution trace autoregressively — 5 tokens per step (`[byte0, byte1, byte2, byte3, commit]`). Each step's value is computed by the transformer's 10-layer forward pass: instruction fetch → operand resolution → ALU → carry propagation → modular reduction.

Every weight is hand-crafted. The 40-dimensional embedding space is allocated like CPU registers: dim 0 holds byte values (never modified — the carry trick), dims 5-6 encode quadratic position addresses, dims 10-15 flag opcodes, dims 23-25 hold ALU operands and results.

## Quick Start

```bash
# Install dependencies
pip install torch numpy

# Build the Rust inference engine (optional, ~50x faster)
cd rust_engine && maturin develop --release && cd ..

# Run all tests (21/21)
python -c "from autoregressive_interpreter import test_native; test_native()"
```

## What It Computes

**Native ops** (computed in weights): ADD, SUB, MUL (32-bit with carry chains), comparisons (24-bit), EQZ, CONST, locals, control flow.

**Compiler-decomposed ops**: DIV, REM, SHL, SHR — the `mini_c.py` compiler emits loops of native ops, like CPU microcode. `a / b` becomes `while (a >= b) { a -= b; q++ }`.

### Write Programs with the C-like DSL

```python
from mini_c import Compiler, var, lit, add, mul, le, assign, output_int, while_loop

c = Compiler()
code, _ = c.compile([
    assign('a', lit(48)), assign('b', lit(18)),
    while_loop(ne(var('b'), lit(0)), [
        assign('t', mod(var('a'), var('b'))),
        assign('a', var('b')),
        assign('b', var('t'))]),
    output_int(var('a'))  # GCD = 6
])
```

## Test Results (2026-03-20)

```
Model: 8,412,800 params (d_model=40, 20 heads, 10 layers)
Hardware: RTX 3060, Rust inference engine

  3 + 5 = 8                   PASS    17 tok/s
  7 * 13 = 91                 PASS    18 tok/s
  200 + 200 = 400             PASS    17 tok/s
  fib(10) = 55                PASS   483 tok/s
  fib(20) = 6765              PASS   865 tok/s
  fib(30) = 832040            PASS  1124 tok/s
  5! = 120                    PASS   204 tok/s
  gcd(48,18) = 6              PASS   412 tok/s
  gcd(1071,462) = 21          PASS   645 tok/s
  is_prime(17) = 1            PASS   798 tok/s
  collatz(7) = 16             PASS   800 tok/s
  ...
  Result: 21/21
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete technical breakdown including dimension allocation, layer-by-layer descriptions, and the carry trick.

Key specs:
- **Model**: d_model=40, n_heads=20, n_layers=10, head_dim=2, d_ffn=256
- **Vocab**: 520 tokens (256 bytes + opcodes + control)
- **Precision**: float64 (required for exact carry arithmetic)
- **Max sequence**: 200,000 positions (600 instructions + trace)

## Repository Structure

```
llm-computer/
├── autoregressive_interpreter.py  # Core: weight setup, encoding, generation, tests
├── model.py                       # VanillaTransformer (vanilla PyTorch)
├── wasm_vm.py                     # Reference WASM VM
├── mini_c.py                      # C-to-WASM compiler (DIV/REM decomposition)
├── compiler.py                    # TraceVocab (token encoding)
├── train.py                       # Training pipeline (research reference)
├── train_hybrid.py                # Hybrid training (research reference)
├── wasm_model_big.pt              # Best trained model (3.4M params, research)
├── ARCHITECTURE.md                # Full technical architecture
├── test_results.txt               # Verified test output
├── rust_engine/
│   ├── src/lib.rs                 # Rust inference + fast VM (1.2M traces/sec)
│   ├── Cargo.toml
│   └── pyproject.toml
└── archive/                       # Superseded experimental files
```

## Known Limitations

- **Control flow** requires a VM trace for the IP sequence (hybrid approach)
- **DIV/REM** not natively computed — compiler generates subtraction loops (slow for large dividends)
- **Comparisons** limited to 24-bit operands (3 bytes)
- **MUL** limited to 16-bit inputs (products up to 65,536)
- **Autoregressive generation** is inherently sequential (~17 tok/s simple, ~1124 tok/s with Rust engine on long traces)

## Training (Research Direction)

A trained model (d_model=128, 3.4M params) achieves 99.22% token accuracy and passes 11/11 ops on simple programs. However, it **memorizes arithmetic** rather than generalizing — it fails on operands > 100. The compiled interpreter generalizes perfectly because carry chains are algorithms, not memorized patterns. See `train.py` and `train_hybrid.py` for the training pipeline.
