# LLM-as-Computer: Complete Architecture

Following [Percepta's "Can LLMs Be Computers?"](https://percepta.ai/blog/can-llms-be-computers)

## 1. What We Built

A WebAssembly interpreter compiled into the weights of a vanilla transformer. Programs are encoded as input tokens. The model generates execution traces step by step through its forward pass — no external tools, no VM at inference time for arithmetic. The transformer IS the computer.

The primary product is the **compiled interpreter**: hand-crafted weights that implement WASM operations as circuits inside attention heads and feed-forward networks. Programs written in a C-like DSL are compiled to WASM instructions, encoded as tokens, and executed by the model autoregressively.

This is not a trained model. Every weight is set by hand to implement a specific function. The forward pass performs the same computation a reference VM would, except the "CPU" is attention + FFN.

## 2. The Approach: Compiled Weights

We hand-craft every weight in the transformer to implement WASM execution. Each layer has a specific role: instruction fetch, operand resolution, byte fetch, ALU computation, carry propagation, modular reduction. The result is a universal interpreter — the same weights execute any program.

### Native Operations (computed in weights)

These operations are implemented directly as circuits in the attention heads and FFN layers:

- **ADD**: 32-bit with carry chains across 4 bytes. Layer 2 FFN computes per-byte sums, layers 3-7 propagate carries.
- **SUB**: 32-bit with borrow chains. Same carry infrastructure, inverted.
- **MUL**: 16-bit inputs (products up to 65,536). Bilinear gates compute cross-term products (a[i]*b[j]), two-stage modular reduction (mod 4096 then mod 256) extracts result bytes. Layers 3-9.
- **Comparisons** (EQ, NE, LT_S, GT_S, LE_S, GE_S): 24-bit using 256x byte-1 and 65536x byte-2 weight scaling. Layer 2 FFN.
- **EQZ**: Tests if operand is zero. Layer 2 FFN.
- **CONST**: 32-bit immediate values packed into 4 bytes. Layer 2 FFN pass-through.
- **Locals** (LOCAL_GET, LOCAL_SET, LOCAL_TEE): Copy via explicit-address attention. Layer 0 fetch + layer 2 copy gate.
- **Control flow** (IF, BLOCK, LOOP, BR, BR_IF): Hybrid approach — VM provides the IP sequence (which instruction to execute at each step), model computes all values at runtime via stack matching.

### Compiler-Decomposed Operations

These operations cannot be natively computed in a single forward step because they require variable-dependent iteration. The `mini_c.py` compiler decomposes them into loops of native ops, analogous to CPU microcode:

- **DIV**: `a / b` becomes `while (a >= b) { a -= b; q += 1 }` using SUB, ADD, GE_S.
- **REM**: `a % b` becomes `while (a >= b) { a -= b }` — remainder is left in `a`.
- **SHL**: `a << b` becomes `repeat b times: a = a + a` — repeated doubling via ADD.
- **SHR**: `a >> b` becomes `compute 2^b via SHL, then divide a by 2^b via DIV decomposition`.

### Baked Fallback Operations

These operations are encoded as CONST instructions with per-step baked values injected via position embeddings. The hybrid encoder pre-computes their results and writes them into PE dim 16:

- **AND**, **OR**, **XOR**: Bitwise operations. The model treats them as constants whose values happen to be correct.

## 3. Architecture Specs

```
d_model   = 40          # embedding dimension
n_heads   = 20          # attention heads per layer
n_layers  = 10          # transformer layers
d_ffn     = 256         # feed-forward network width (256 gates for byte-level step functions)
head_dim  = 2           # dims per head (enables O(log n) convex hull attention)
vocab     = 520         # token vocabulary size
BIG       = 50,000,000  # gate suppression scale (must exceed max 24-bit operand contribution ~33.4M)
MAX_SEQ   = 200,000     # maximum sequence length
Parameters: 8,412,800
Precision: float64      # exact computation, no f32 rounding errors
```

The model uses `nn.MultiheadAttention` with `bias=False`, a gated FFN (`gate, val = ff_in(x).chunk(2); out = ff_out(relu(gate) * val)`), and learned position embeddings. Standard PyTorch. Nothing exotic except the weight values.

## 4. Trace Format

Each execution step produces 5 tokens:

```
[byte0, byte1, byte2, byte3, commit]
```

- **byte0-byte3**: Little-endian i32 value (the result pushed to the stack, or the value stored to a local, or zero for output/halt).
- **commit**: Encodes what happened:
  - `0-253`: Stack size after this instruction. Used by future steps for operand resolution via content-matching attention.
  - `254`: OUTPUT — this step emits a value to the output stream.
  - `255`: HALT — execution complete.

The commit token is the key to runtime operand resolution. When the model needs operand A (at stack position `ss`), it uses content-matching attention to find the most recent commit token whose value equals `ss`. The byte values adjacent to that commit token are the operand.

## 5. Program Encoding

Each instruction is encoded as 6 tokens:

```
[opcode, imm_b0, imm_b1, imm_b2, imm_b3, delta+1]
```

- **opcode**: `Op.value + 260` (offset into vocabulary).
- **imm_b0-b3**: Immediate value bytes (little-endian). For CONST, this is the constant. For LOCAL_GET/SET, byte 0 is the local index.
- **delta+1**: Stack depth change + 1. `2` = push (CONST, LOCAL_GET), `0` = net pop (ADD, SUB, OUTPUT), `1` = neutral (LOCAL_TEE, HALT).

Programs are padded to `MAX_INST = 600` instructions (3,600 tokens), followed by a SEP token (519), then the trace begins at position 3,601.

Structural WASM ops (BLOCK, LOOP, IF, ELSE, END, BR, BR_IF) are stripped from the program encoding. They don't produce trace steps. The hybrid encoder handles control flow by injecting the VM-computed IP sequence into position embeddings.

## 6. Dimension Allocation (d_model = 40)

Every dimension has a specific purpose. The table below is the complete allocation:

| Dim | Name | Source | Purpose |
|-----|------|--------|---------|
| 0 | byte_value | Token embedding | Input byte value (0-255). **NEVER modified by any layer** — the carry trick depends on this. |
| 1 | stack_key / prevB | L0 FFN / L3 attn | After L0: filtered stack_size squared (commit positions only). After L3: previous byte operand B. |
| 2 | opA_byte1 | L2 attn head 2 | Operand A byte at slot k-1 (for cross-byte carry). |
| 3 | is_sep | PE | 1.0 at the SEP position. |
| 4 | is_trace | PE | 1.0 for all trace positions. |
| 5 | position | PE | Absolute position in sequence. |
| 6 | -S_QUAD * pos² | PE | Quadratic term for position-based addressing (S_QUAD=100). |
| 7 | step_number / IP | PE | In program: instruction index. In trace: step number (or VM instruction pointer for hybrid). |
| 8 | slot | PE | Byte index within a step (0-4). |
| 9 | is_commit_slot | PE | 1.0 at slot 4 (the commit position). |
| 10 | is_const | Token embed / L0 attn | Opcode flag: I32_CONST. |
| 11 | is_add | Token embed / L0 attn | Opcode flag: I32_ADD. |
| 12 | is_sub | Token embed / L0 attn | Opcode flag: I32_SUB. |
| 13 | is_mul | Token embed / L0 attn | Opcode flag: I32_MUL. |
| 14 | is_output | Token embed / L0 attn | Opcode flag: OUTPUT. |
| 15 | is_halt | Token embed / L0 attn | Opcode flag: HALT. |
| 16 | immediate_byte | L0 attn head 3 | Immediate value byte for CONST ops. |
| 17 | own_stack_size | L0 attn head 10-11 | Previous commit's stack_size + delta+1. Net stack size for this step. |
| 18 | operand_B_commit_pos | L1 attn head 0 | Position of the commit token for operand B (content matching). |
| 19 | operand_A_commit_pos / commit_key_quad | L1 attn head 1 / L0 FFN | Position of commit token for operand A. Also used for commit key quadratic addressing. |
| 20 | fetch_addr_A | L1 FFN | Byte fetch address for operand A: commit_pos + slot. |
| 21 | fetch_addr_B | L1 FFN | Byte fetch address for operand B: commit_pos + slot. |
| 23 | opA_byte | L2 attn | Operand A byte value at current slot. |
| 24 | opB_byte | L2 attn | Operand B byte value at current slot. |
| 25 | ALU result | L2+ FFN | Accumulates the ALU computation result. Output head reads this. |
| 26 | cleared / bias | L2 head 3 / PE | Operand B byte1 (cleared after use). PE sets bias = 1.0. |
| 27 | bias | PE | Constant 1.0. Used as bias term in various computations. |
| 28 | commit_key_offset / is_commit_input | PE | COMMIT_OFFSET (256.0) at commit positions. Also slot-0 indicator for carry suppression. |
| 29 | MUL scratch / is_le_s | L3 FFN / Token embed | MUL: stores a[k-1]*b[k-1] for carry computation. Also LE_S opcode flag (safe: MUL and LE_S never co-occur). |
| 30 | is_ge_s / k-2 fetch | Token embed / L3 attn | GE_S opcode flag. Also used for fetching operand byte at k-2. |
| 31 | is_lt_s | Token embed | LT_S opcode flag. |
| 32 | is_gt_s | Token embed | GT_S opcode flag. |
| 33 | is_eq | Token embed | EQ opcode flag. |
| 34 | is_ne | Token embed | NE opcode flag. |
| 35 | is_eqz | Token embed | EQZ opcode flag. |
| 36 | is_slot_2 | PE | 1.0 at slot 2 only. Exact slot gating for byte-2 operations. |
| 37 | is_slot_3 | PE | 1.0 at slot 3 only. Exact slot gating for byte-3 operations. |
| 38 | opA_byte2 | L2 attn head 4 | Operand A byte at slot k-2. |
| 39 | opB_byte2 | L2 attn head 5 | Operand B byte at slot k-2. |

## 7. Layer Architecture (10 Layers)

Each layer has a specific function. Together they form a pipeline that fetches instructions, resolves operands, computes results, and propagates carries.

### L0: Instruction Fetch + Previous Commit Reader

**Attention (12 active heads)**: Heads 0-5 fetch instruction fields (opcode flags, immediate bytes) from the program region into the current trace position. Uses quadratic addressing: query encodes step number, key encodes instruction index, and the quadratic term (`position - S_QUAD * position²`) ensures exact position matching.

Heads 10-11 read the previous commit token to determine `own_stack_size`. Uses position-based targeting (`dim 5 - dim 8 = pos - slot`) rather than step_number (which gets overwritten by IP in hybrid mode).

**FFN**: Computes commit key components. At commit positions, writes `stack_size²` (filtered by `is_commit_slot`) for quadratic content matching in L1.

### L1: Stack-Based Operand Resolution

**Attention (2 heads)**: Content-matching attention on commit tokens. Head 0 finds operand B (stack_size = own_ss + 1), head 1 finds operand A (stack_size = own_ss). The key is `dim 0 + COMMIT_OFFSET` at commit positions, so non-commit tokens (which have raw byte values in dim 0) never match.

**FFN**: Computes byte fetch addresses. `fetch_addr = commit_position + slot_offset`, written to dims 20-21.

### L2: Byte Fetch + ALU

**Attention (6 heads)**: Heads 0-1 fetch operand bytes at current slot (opA_byte, opB_byte) from the positions computed in L1. Heads 2-3 fetch operand bytes at slot k-1 (for carry computation). Heads 4-5 fetch bytes at slot k-2 (for MUL cross terms).

**FFN (256 gates)**: The main ALU. Computes:
- ADD/SUB: per-byte sum/difference → dim 25
- MUL: byte-0 product (a[0]*b[0]) → dim 25
- CONST: pass through immediate byte → dim 25
- LOCAL_GET/SET/TEE (copy gate): pass through fetched byte → dim 25
- Comparisons (24-bit): `cmp_result = sign(byte0_diff + 256*byte1_diff + 65536*byte2_diff)`, gated by opcode flags → dim 25
- EQZ: `result = (opA_byte == 0 for all slots)` → dim 25
- Commit token: output stack_size from dim 17 → dim 25

### L3: Carry Detection + Cross Terms

**Attention (4 heads)**: Heads 0-1 fetch operand bytes at position k-1 (for carry calculation). Heads 2-3 fetch bytes at k-2 (for MUL).

**FFN**: Computes:
- ADD carry: `carry = (a_byte + b_byte - result_dim0) / 256`. The dim 0 carry trick: since dim 0 is NEVER modified, it holds the previous byte's result. The raw sum minus dim 0, divided by 256, gives the exact carry.
- MUL bilinear products: `a[k]*b[k-1]` and `a[k-1]*b[k]` cross terms.
- SUB borrow propagation.

### L4: Byte-2/3 Cross Terms + Carry Recomputation

**Attention**: Fetches bytes from 2 positions back in the trace for MUL byte-2/3 cross terms.

**FFN**: Computes MUL byte-2 cross terms (`a[0]*b[2]`, `a[2]*b[0]`, `a[1]*b[1]`). Recomputes carry_0 with exact slot gating (PE dims 36-37 ensure byte-2 and byte-3 operations only fire at the correct slots).

### L5: carry_0 Propagation

**FFN**: Adds carry_0 to byte1_raw. Prepares the intermediate sum for the next carry stage.

### L6: carry_1 Propagation + ADD mod 256

**FFN**: Computes carry_1 from byte-1 result. For ADD: applies mod 256 to get final byte values. For SUB: applies modular correction.

### L7: MUL mod 4096 (slot 0) + MUL Carry + carry_2

**FFN**: First stage of MUL modular reduction at slot 0. Computes MUL carry from byte 0 to byte 1 (product mod 256, carry = product / 256). Propagates carry_2 for byte-3.

### L8: MUL mod 4096 (all slots)

**FFN**: Extends the mod 4096 reduction to all non-commit slots. Uses 16 step-function pairs to compute `x mod 4096` for products that can reach up to 65,536.

### L9: MUL mod 256 (all slots) + Final Copy

**FFN**: Second stage of MUL modular reduction: mod 256 from the mod 4096 intermediate. Uses 15 step-function pairs. Copies final result to dim 26 for the output head to read.

### Output Head

Quadratic byte decoding maps dim 25/26 values to token logits. For byte tokens (0-255): `logit(v) = -(dim25 - v)² * S_HEAD`, producing a sharp peak at the correct byte value. For commit tokens: maps dim 17 (stack_size) through a similar quadratic to token 0-253, or emits 254/255 for OUTPUT/HALT.

## 8. Key Innovations

### Dim 0 Carry Trick

The most important design decision. Token embeddings write `byte_value` to dim 0, and **no layer ever modifies dim 0**. This means:
- At slot k (byte position k within a 5-token step), dim 0 still holds the byte value of the token at position k within the current step.
- After the ALU computes `raw_sum = a_byte + b_byte` into dim 25, the carry for the NEXT byte is `(raw_sum - dim0) / 256`.
- This works because dim 0 already contains `raw_sum mod 256` (it's the actual output byte, which equals the result mod 256).

Without this trick, computing carry would require an explicit mod operation, which would need its own carry infrastructure — a circular dependency.

### Two-Stage Modular Reduction

MUL can produce byte products up to 255*255 = 65,025. A single mod 256 pass with ReLU step functions would need ~254 gate pairs. Instead:
1. **mod 4096**: 16 step-function pairs reduce to range [0, 4095]. Layer 8.
2. **mod 256**: 15 step-function pairs reduce [0, 4095] to [0, 255]. Layer 9.

Total: 31 gate pairs instead of 254. This is why `d_ffn = 256` — it provides enough gates for both stages plus other ALU operations.

### Exact Slot Gating (PE dims 36-37)

Byte-2 and byte-3 operations (MUL cross terms, carry_2) must ONLY fire at slots 2 and 3, not at slots 0, 1, or 4. PE dims 36 and 37 are set to 1.0 only at the exact slot, providing a hard gate that FFN weights multiply against.

### Quadratic Addressing

Position embeddings include both `position` (dim 5) and `-S_QUAD * position²` (dim 6). Attention keys use `(position, -S_QUAD * position²)` and queries use `(target_position, 1)`. The dot product is `target * position - S_QUAD * position²`, which is maximized at `position = target / (2 * S_QUAD)`. With proper scaling, this gives exact position targeting — the attention mechanism can find any specific position in O(1) via argmax, and O(log n) using the convex hull.

### Structural Pop Correction

BR_IF and IF pop the condition value from the stack but don't produce trace steps (they're structural ops). The hybrid encoder tracks these "structural pops" and corrects dim 17 (own_stack_size) via PE injection at the next executable step. Without this, the stack size accounting drifts and operand resolution breaks.

## 9. Compiler Decomposition

The `mini_c.py` compiler decomposes operations that cannot be natively computed into loops of native ops. This is analogous to CPU microcode — a single high-level operation expands into a sequence of primitive instructions.

### DIV Decomposition: `a / b`

```
q = 0
while a >= b:    # GE_S
    a = a - b    # SUB
    q = q + 1    # ADD, CONST(1)
result = q
```

This is O(a/b) steps. For `collatz(7)`, each division by 2 requires up to N/2 subtraction iterations, which is why the trace reaches 18,025 tokens for 16 Collatz steps.

### REM Decomposition: `a % b`

Same loop as DIV, but returns `a` (the remainder) instead of `q` (the quotient).

### SHL Decomposition: `a << b`

```
repeat b times:
    a = a + a    # ADD (doubling)
result = a
```

### SHR Decomposition: `a >> b`

```
pow = 1
repeat b times:
    pow = pow + pow    # compute 2^b
result = a / pow       # uses DIV decomposition
```

The compiler emits these expansions at compile time. The transformer sees only native ops (CONST, ADD, SUB, GE_S, LOCAL_GET/SET, BLOCK, LOOP, BR, BR_IF) — it never encounters a DIV or SHL instruction.

## 10. Rust Inference Engine

The `rust_engine/` directory contains a PyO3-based Rust extension that accelerates both inference and training data generation.

### `generate_trace_multilayer()`

Full multi-layer inference reimplemented in Rust. Mirrors the Python transformer forward pass exactly (same weight layout, same layer structure, same FFN gating), but runs at native speed with no Python overhead.

Each of the 20 attention heads per layer maintains an incremental **Hull2D** — a 2D convex hull of all past key-value pairs. For head_dim=2, finding the max-dot-product key reduces to a "supporting point on the convex hull" query, solvable in O(log n) via binary search on the hull boundary.

Active head detection: at initialization, the engine scans each head's in_proj and out_proj weights. If all weights are zero, the head is skipped entirely. Most heads in most layers are inactive (only ~12 of 200 total head-slots carry non-zero weights), so this cuts computation significantly.

Performance: ~1,124 tok/s on fib(30) (2,320 tokens). Simple programs run slower (~17 tok/s) due to Python startup overhead; the Rust engine amortizes this over longer traces.

### `fast_vm_trace()`

A stripped-down WASM VM implemented in Rust for generating training data. Takes flat arrays of opcodes and operands, returns flat trace arrays. Achieves ~1.2M traces/sec — roughly 1000x faster than the Python VM. Used exclusively for training data generation, not for inference.

## 11. Test Results

Verified on 2026-03-20. Hardware: RTX 3060 (Vast.ai), Rust inference engine.

### Native Interpreter: 21/21 PASS

| Test | Tokens | Time | Tok/s | Result |
|------|--------|------|-------|--------|
| 3 + 5 | 25 | 1.46s | 17 | 8 |
| 7 * 13 | 25 | 1.40s | 18 | 91 |
| 10 - 3 | 25 | 1.44s | 17 | 7 |
| 2*(3+5) | 35 | 2.19s | 16 | 16 |
| 200 + 200 | 25 | 1.51s | 17 | 400 |
| 10 >= 5 | 25 | 1.45s | 17 | 1 |
| 5 == 5 | 25 | 1.52s | 16 | 1 |
| if 10>=5 | 40 | 1.48s | 27 | 1 |
| sum(1..3) | 235 | 2.21s | 106 | 6 |
| fib(5) | 445 | 1.60s | 278 | 5 |
| fib(10) | 820 | 1.70s | 483 | 55 |
| fib(15) | 1,195 | 1.79s | 669 | 610 |
| fib(20) | 1,570 | 1.82s | 865 | 6,765 |
| sum(1..10) | 655 | 1.58s | 414 | 55 |
| 5! | 295 | 1.45s | 204 | 120 |
| gcd(48,18) | 655 | 1.59s | 412 | 6 |
| is_prime(17) | 1,440 | 1.81s | 798 | 1 |
| collatz(7) | 18,025 | 22.53s | 800 | 16 |
| fib(25) | 1,945 | 2.06s | 944 | 75,025 |
| fib(30) | 2,320 | 2.06s | 1,124 | 832,040 |
| gcd(1071,462) | 1,075 | 1.67s | 645 | 21 |

Notes:
- GCD and primality use compiler-decomposed DIV/REM (repeated subtraction loops).
- `collatz(7)` produces 18,025 tokens because each division is decomposed into O(n) subtractions.
- `fib(30) = 832040` — correct via 32-bit carry chains. All arithmetic generalizes perfectly.

### Explicit-Address Interpreter: 27/28

Same weights, trace-compiled program encoding. One timeout on collatz(7) due to encoding overhead on 18,025-token trace.

## 12. Training Pipeline (Research Direction)

Training was explored as a complement to compiled weights. The goal was to learn operations that resist hand-crafting (DIV, REM, bitwise). This is a research direction, not the primary product.

### Trained Model Architecture

```
d_model = 128, n_heads = 64, n_layers = 12, d_ffn = 512
head_dim = 2, ~3.4M parameters
Trained on Vast.ai RTX 3090 ($0.12/hr)
Best checkpoint: 99.22% token accuracy, 11/11 ops pass (autoregressive)
```

### Training Process

1. Generate random WASM program (arithmetic, chains, locals, loops, conditionals).
2. Run reference VM to get ground-truth execution trace.
3. Encode as tokens: `input = program + trace[:-1]`, `target = trace` (shifted by 1).
4. Teacher forcing with cross-entropy loss on trace positions only (program positions masked with -100).
5. AdamW optimizer, cosine learning rate schedule.

### Data Sources

1. **Random program generator**: arithmetic ops, expression chains, locals, loops, conditionals.
2. **WASM spec test suite**: 323 test vectors from WebAssembly/spec (i32.wast).
3. **Rust fast VM**: 1.2M traces/sec for massive data throughput.

### Key Insight: Diverse Training Data

Simple `CONST, CONST, OP` programs cause positional shortcuts. The model learns "byte at position 10 = f(byte at position 0, byte at position 5)" instead of learning the operation semantics. Fix: structurally diverse programs (expression chains, locals, loops) force the model to learn operation SEMANTICS because operand positions vary.

### Limitation: Memorization vs. Generalization

The trained model memorizes arithmetic rather than generalizing it. It achieves high accuracy on operands in the training distribution (0-255) but fails on larger operands. This is fundamentally different from the compiled interpreter, which implements exact algorithms (carry chains, modular reduction) that work for any input.

The compiled interpreter is the primary product. The trained model is shipped as a research reference.

## 13. Repository Structure

```
llm-computer/
├── autoregressive_interpreter.py  # Core: weight compilation, encoding, generation (d_model=40)
├── model.py                       # VanillaTransformer (standard PyTorch, no custom ops)
├── wasm_vm.py                     # Reference WASM VM (full instruction set)
├── mini_c.py                      # C-like DSL → WASM compiler (decomposes DIV/REM/SHL/SHR)
├── compiler.py                    # TraceVocab (token vocabulary) + TraceCompiler
├── weight_compiler.py             # Original d_model=36 per-program weight compiler (Phase 1)
├── general_interpreter.py         # Universal d_model=36 interpreter (predecessor)
├── hull_kv_cache.py               # Python ConvexHull2D + HullKVCache (O(log n) attention)
├── executor.py                    # Execution engine (VM and transformer modes)
├── demo.py                        # Demo: addition, fibonacci, sudoku
├── demo_sandbox.py                # Sandbox demo
├── sandbox.py                     # Sandbox execution substrate
├── wasm_runtime.py                # Full WASM binary runtime (pywasm backend)
├── train.py                       # Training pipeline (random programs + teacher forcing)
├── train_hybrid.py                # Hybrid training (freeze compiled layers, train FFN gates)
├── train_v2.py                    # Training v2 experiments
├── train_modal.py                 # Modal.com GPU wrapper for cloud training
├── run_modal.py                   # Modal.com runner
├── test_results.txt               # Verified test results (2026-03-20)
├── wasm_model_big.pt              # Trained model checkpoint (3.4M params)
├── wasm_model_trained.pt          # Trained model checkpoint
├── wasm_model_final.pt            # Trained model checkpoint
├── wasm_model_small.pt            # Small trained model checkpoint
├── requirements.txt               # Python dependencies
├── ARCHITECTURE.md                # This file
└── rust_engine/
    └── src/lib.rs                 # Rust inference engine (Hull2D + fast VM, PyO3 bindings)
```

## 14. Known Limitations

These are honest limitations of the current system:

- **Control flow requires VM for IP sequence.** The model cannot determine which instruction to execute next when branches or loops are involved. The hybrid encoder runs the reference VM to extract the instruction pointer sequence, then injects it into position embeddings. Values are still computed at runtime.

- **DIV/REM not natively computed.** Division and remainder are decomposed by the compiler into O(a/b) subtraction loops. This means `collatz(7)` takes 18,025 tokens instead of ~160 if DIV were native. The fundamental issue: implementing `a / b` in a single forward step requires a threshold function that depends on both operands — impossible with fixed weights.

- **Comparisons limited to 24-bit (3 bytes).** The weight encoding uses 256x and 65536x scaling for byte-1 and byte-2 contributions. Byte 3 would require 16,777,216x scaling, which exceeds precision limits. Values above 16,777,215 may compare incorrectly.

- **MUL limited to 16-bit inputs.** Products can reach at most 65,536 (256*256). The two-stage modular reduction handles this range. Larger products overflow the mod 4096 stage. For the programs tested (including fib(30) = 832,040), intermediate multiplications stay within this range because the fibonacci recurrence uses addition, not multiplication of large values.

- **No memory operations in native interpreter.** I32_LOAD and I32_STORE are implemented in the reference VM but not in the compiled transformer weights. Programs requiring memory (arrays, heap allocation) must use the VM or the sandbox.

- **Autoregressive generation is slow.** Simple programs: ~17 tok/s (dominated by Python startup and model initialization). Long programs with Rust engine: ~1,124 tok/s for fib(30). For comparison, the reference VM executes millions of steps per second. The transformer approach trades speed for the property that all computation is visible in the token trace.

- **float64 precision required.** The compiled weights use large constants (BIG = 50M, S_QUAD = 100) that cause numerical errors in float32. The model runs in float64 to ensure exact computation. This doubles memory and may prevent GPU acceleration on hardware that penalizes f64.

- **Program size limited to 600 instructions.** MAX_INST = 600 with 6 tokens each = 3,600 program tokens. Programs compiled from C via mini_c.py with heavy use of DIV/REM decomposition can approach this limit. The collatz program uses ~40 raw instructions, which expands to ~100+ after DIV/REM decomposition.
