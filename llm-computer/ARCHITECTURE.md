# LLM-as-Computer: Transformer Architecture Notes

Following [Percepta's "Can LLMs Be Computers?"](https://percepta.ai/blog/can-llms-be-computers) blog post.
A WebAssembly interpreter compiled into vanilla transformer weights.

## Model Specification

```
d_model = 36       # embedding dimension
n_heads = 18       # attention heads (head_dim = 2 each)
n_layers = 7       # transformer layers (L0-L6)
d_ffn = 36         # FFN hidden dimension (gated bilinear: relu(gate) * value)
max_seq = 200000   # position embedding capacity
vocab = 520        # byte tokens (0-255) + opcodes + SEP
```

The 2D head dimension enables O(log n) convex hull queries for attention — the blog's core speedup.

## Trace Format

Each execution step produces 5 tokens:
```
[byte0, byte1, byte2, byte3, commit]
```
- bytes 0-3: little-endian i32 value (result of the instruction)
- commit: stack_size (0-253), 254 = OUTPUT, 255 = HALT

## Program Encoding (INST_SIZE = 6)

```
[opcode, imm_b0, imm_b1, imm_b2/src_a, imm_b3/src_b, delta+1]
```
- For I32_CONST: positions 1-4 = full 32-bit immediate (little-endian)
- For other ops: positions 3-4 = explicit addresses (compiled) or 0 (native)
- Position 5: delta+1 encoding (0=pop, 1=neutral, 2=push)

## Dimension Allocation (d_model = 36)

### Token Embedding (set once)
| Dim | Name | Description |
|-----|------|-------------|
| 0 | byte_value | 0-255 for byte tokens; preserved through ALL layers |
| 10 | is_const | I32_CONST opcode flag |
| 11 | is_add | I32_ADD opcode flag |
| 12 | is_sub | I32_SUB opcode flag |
| 13 | is_mul | I32_MUL opcode flag |
| 14 | is_output | OUTPUT opcode flag |
| 15 | is_halt | HALT opcode flag |
| 22 | is_copy | LOCAL_GET/SET/TEE opcode flag |
| 29-35 | cmp_flags | LE_S, GE_S, LT_S, GT_S, EQ, NE, EQZ flags |

### Position Embedding
| Dim | Name | Description |
|-----|------|-------------|
| 1 | is_program | 1.0 in program region |
| 2 | is_opcode_pos | 1.0 at opcode positions in program |
| 3 | is_sep | 1.0 at SEP position |
| 4 | is_trace/src_a | 1.0 in trace + src_a offset for locals (via _set_ip_pe) |
| 5 | position | absolute position (0..MAX_SEQ) |
| 6 | -S_QUAD*pos^2 | quadratic key for positional addressing |
| 7 | step_number/IP | step index (native) or instruction pointer (hybrid via _set_ip_pe) |
| 8 | slot | byte index within step (0-4) |
| 9 | is_commit_slot | 1.0 at slot 4 (predicts commit token) |
| 27 | bias | always 1.0 |
| 28 | is_commit_input | 1.0 where input token IS a commit (= slot 0 indicator) |

### Per-Step PE Injection (_set_ip_pe)
| Dim | Name | When |
|-----|------|------|
| 7 | IP | instruction index for control flow programs |
| 4 | src_a + 1.0 | explicit local variable source for LOCAL_GET/SET |
| 16 | baked_byte | per-byte result for unsupported ops (DIV, REM) |
| 17 | structural_pops | -N correction for br_if/if/drop pops between steps |
| 20 | stack_size | backup at commit positions |

### Residual Stream (written by layers)
| Dim | Written By | Content |
|-----|-----------|---------|
| 1 | L0 FFN | stack_key = byte_value + COMMIT_OFFSET at commit positions |
| 2 | L2 attn head 2 | opA byte 1 (for 16-bit comparisons) |
| 3 | L1 FFN | fetch_addr_B |
| 17 | L0 heads 10+11 | prev_ss + delta+1 (+ PE correction for structural pops) |
| 18 | L1 head 0 | operand_B_commit_pos |
| 19 | L0 FFN / L3 head 0 | commit key quadratic / prevA (for carry) |
| 20 | L1 head 1 | operand_A_commit_pos |
| 21 | L1 FFN | fetch_addr_A |
| 23 | L2 head 0 | opA_byte (at current slot) |
| 24 | L2 head 1 | opB_byte (at current slot) |
| 25 | L2-L6 FFN | ALU result accumulator (output head reads this) |
| 26 | L2 head 3 / L3 FFN | opB byte 1 / cleared by L3 gate 6 |
| 29 | L3 FFN | MUL scratch: a0*b0 (at slot 1) or a1*b1 (at slot 2) |

## Layer Architecture

### L0: Instruction Fetch + Previous Commit

**Attention (12 heads used):**
- Heads 0-2, 6-9: fetch opcode flags from program (pairs of dims)
- Head 3: fetch immediate byte (+ byte_idx offset for multi-byte CONST)
- Head 4: fetch src_a from program position 3
- Head 5: fetch src_b from program position 4
- Head 10: read previous commit token → dim 17 (prev_ss)
  - **Key fix**: uses position-based targeting `Q = [2S*dim5 - 2S*dim8, 1]`
  - target = pos - slot = previous step's commit position
  - Independent of IP (works for both straight-line and control flow)
- Head 11: fetch delta+1 from program position 5 → adds to dim 17

**FFN (3 gates):**
- Gate 0: stack_key = byte_value + COMMIT_OFFSET at commit input positions → dim 1
- Gate 1: -(stack_key + OFFSET)^2 at commit positions → dim 19 (for quadratic matching)
- Gate 2: recency bias (position) at commit positions → dim 19

### L1: Operand Resolution (Stack Matching)

**Attention (2 heads):**
- Head 0: find most recent commit with stack_size = dim17 → opB commit position → dim 18
- Head 1: find most recent commit with stack_size = dim17 - 1 → opA commit position → dim 20

Content matching via quadratic scoring: score = -S_STACK*(key - target)^2 + position_bias

**FFN (3 gates):**
- Gate 0: fetch_addr_A from opA commit pos (binary ops + comparisons + EQZ) → dim 21
- Gate 1: fetch_addr_B from opB commit pos (binary ops + comparisons) → dim 3
- Gate 2: explicit fetch_addr_A for LOCAL ops (from PE dim 4 src_a) → adds to dim 21

### L2: Byte Fetch + ALU

**Attention (4 heads):**
- Head 0: fetch opA byte at current slot → dim 23
- Head 1: fetch opB byte at current slot → dim 24
- Head 2: fetch opA byte at slot+1 (next byte, for 16-bit comparisons) → dim 2
- Head 3: fetch opB byte at slot+1 → dim 26

**FFN (35 gates) — the ALU:**
- Gate 0: ADD (opA + opB, all byte slots except commit)
- Gate 1: CONST (immediate byte, all slots except commit)
- Gate 2: SUB (opA - opB, slot 0 only)
- Gate 3: MUL (opA * opB, slot 0 only via bilinear trick)
- Gate 4: COPY (opA passthrough for LOCAL ops)
- Gates 7-28: Comparisons (LT, GT, LE, GE, EQ, NE) + EQZ
  - **16-bit**: gates include `256*a_byte1` and `256*b_byte1` terms
  - Compares reconstructed 16-bit values a0+256*a1 vs b0+256*b1
  - EQZ checks a0+256*a1 == 0 (gates 26-28)
- Gate 29: Universal commit gate: `relu(dim17 - 1 + BIG*is_commit - BIG)`
  - Computes: prev_ss + delta+1 - 1 + structural_pops_correction = new_stack_size
- Gate 33: OUTPUT commit (254)
- Gate 34: HALT commit (255)

**BIG = 200000** for proper 16-bit gate suppression (max 16-bit operand contribution ~131K).

### L3: Carry Detection + MUL Cross Terms

**Attention (2 heads, rerouted to avoid dim conflict with L2 byte-1 heads):**
- Head 0: fetch opA[k-1] (prev byte of operand A) → **dim 19** (was dim 26)
- Head 1: fetch opB[k-1] (prev byte of operand B) → **dim 1** (was dim 2)

**FFN (10 gates):**
- Gate 4: ADD carry +1: relu(prevA + prevB - 255) at slots 1-3
  - Uses dim 28 (is_commit_input) for slot-0 suppression (not +slot, which shifts threshold)
- Gate 5: ADD carry -1: -relu(prevA + prevB - 256) (clamps carry to {0,1})
- Gate 6: clear dim 26 (opB byte 1 from L2, must not reach output head)
- Gate 7: MUL a0*b0 → dim 29 (scratch for carry) at slots > 0
- Gate 8: MUL cross term a[k]*b[k-1] → dim 25 at slots > 0
- Gate 9: MUL cross term a[k-1]*b[k] → dim 25 at slots > 0

### L4: MUL Mod 4096 (Slot 0) + ADD Mod 256 + MUL Carry

**FFN (35 gates):**
- Gates 0-1: ADD-only mod 256 (single -256 subtraction, all slots)
- Gates 2-33: MUL mod 4096 at **slot 0 only** (16 step-function pairs)
  - Gated with `+BIG*is_commit_input + BIG*is_mul - 2*BIG` (slot 0 has is_commit_input=1)
  - Each pair: `-4096 * step(x >= k*4096)` for k=1..16
  - Handles products up to 65536
- Gate 34: MUL carry byte0→byte1 at slots > 0
  - `carry = (a0*b0 - byte0_result) / 256`
  - **Key insight**: dim 0 (byte_value) is NEVER modified by any layer
  - At slot 1, input token = byte 0 result → dim 0 = byte0_result
  - `ff4_out[25, 34] = 1.0/256.0` (exact in float64)

### L5: MUL Mod 4096 (All Slots)

**FFN (32 gates):**
- Gates 0-31: mod 4096 for MUL at all non-commit slots
  - At slot 0: value already < 4096 from L4 (no-op)
  - At slot 1+: reduces cross terms + carry to [0, 4095]

### L6: MUL Mod 256 (All Slots)

**FFN (31 gates):**
- Gates 0-29: mod 256 for MUL at all non-commit slots (15 step-function pairs)
  - Reduces [0, 4095] → [0, 255]
- Gate 30: copy dim 25 → dim 26 (unused, output head reads dim 25 directly)

**Output head reads dim 25 directly** (not dim 26) to avoid the layer-ordering issue where copy and mod-256 are simultaneous in the FFN.

## Step-Function Implementation

Modular reduction `x mod N` uses step-function pairs:
```
-N * step(x >= k*N) = -N * [relu(x - k*N + 1) - relu(x - k*N)]
```
Each pair uses 2 FFN gates. For mod 4096: 16 pairs (k=1..16) = 32 gates.
For mod 256: 15 pairs (k=1..15) = 30 gates.

**Threshold convention**: gate_g at `k*N - 1`, gate_g+1 at `k*N`. This gives exact step at `k*N`:
- x = k*N - 1: relu(0) - relu(-1) = 0 (no subtraction)
- x = k*N: relu(1) - relu(0) = 1 (subtract N)

## Hybrid Encoder (Control Flow)

For programs with control flow (IF, LOOP, BR_IF), the hybrid encoder:

1. **Strips structural ops** from the program (NOP, BLOCK, LOOP, IF, ELSE, END, BR, BR_IF)
2. **Runs VM** to get the execution trace (IP sequence, stack sizes, local sources)
3. **Maps raw IPs** to executable instruction indices
4. **Tracks structural pops**: br_if and if pop the condition from the stack. These pops are recorded as `structural_pops[step]` and injected as corrections into PE dim 17.
5. **Bakes unsupported ops**: DIV, REM, bitwise ops get values injected via PE dim 16
6. **Injects per-step PE**: IP (dim 7), local src_a (dim 4), stack sizes (dim 20), baked values (dim 16), structural pop corrections (dim 17)

## What's Computed Natively (in weights)

| Operation | Byte Range | Mechanism |
|-----------|-----------|-----------|
| ADD | 32-bit | Bilinear gate + carry chain (L3) + mod 256 (L4) |
| SUB | 32-bit | Bilinear gate + carry chain |
| MUL | 16-bit (bytes 0-1) | Bilinear gate + two-stage mod (L4-L6) + carry via dim 0 |
| Comparisons | 16-bit | 256x byte-1 weights in gate inputs |
| EQZ | 16-bit | Same 256x mechanism |
| CONST | 32-bit | 4-byte immediate in instruction encoding |
| LOCAL_GET/SET/TEE | 32-bit | Copy via explicit address attention |

## What's Baked (from VM trace via PE)

| Operation | Reason |
|-----------|--------|
| DIV (i32_div_s) | Not expressible as bilinear product |
| REM (i32_rem_s) | Same |
| MUL byte 2+ | Carry chain too deep for 7 layers (need recomputation from 2+ slots back) |
| AND, OR, XOR | Discontinuous bitwise functions need O(256) step gates |
| SHL, SHR | Same |

## Known Architectural Limits

### MUL Byte 2+ (products > 65535)
At slot 2, the model needs a0 and b0 (from 2 slots back). L3 heads only fetch k-1.
L3 gates 8-9 compute wrong cross terms at slot 2 (a2*b1 + a1*b2 instead of a0*b2 + a2*b0).
**Fix**: Increase N_LAYERS to 9-10, add k-2 fetch heads in a new layer, restructure carry chain.

### Carry Chain Depth
Each byte-to-byte carry requires:
1. Recomputing the raw total from cross terms
2. Subtracting the byte result (dim 0 trick)
3. Dividing by 256 (1/256 output scaling)
Each step needs the carry from the previous byte, creating a serial dependency.
With 7 layers and 4 bytes, the carry chain for byte 3 requires carry_2 → carry_1 → carry_0,
which needs 3 sequential FFN layers after all cross terms are available.

### Gate Budget (D_FFN = 36)
Each FFN layer has exactly 36 gated bilinear units. The two-stage mod (mod 4096 + mod 256)
consumes 32 + 30 = 62 gates across 2 layers. Adding more operations requires either
more layers or larger D_FFN.

### 16-bit Comparison Limit
Comparisons reconstruct 16-bit values from bytes 0-1 using 256x weights.
Values > 65535 need bytes 2-3, requiring additional fetch heads and dim space.
Currently: `sum(1..N)` works for N up to ~65535. Beyond that, the loop comparison fails.

## Rust Engine

The Rust engine (`rust_engine/src/lib.rs`) implements:
- Brute-force O(n) attention for traces < 8192 tokens
- Convex hull O(log n) attention for longer traces (Hull2D structure)
- Active-head detection (skips zero-weight heads for speed)

Hardcoded constants must match Python: `D=36, N_HEADS=18, N_LAYERS=7, HD=2, D_FFN=36, VOCAB=520`.

## Test Results

### Base Suite (21/21 PASS)
Arithmetic, comparisons, conditionals, loops, fib(30)=832040, GCD, primality, Collatz(7).

### Stress Suite (passing)
- fib(40) = 102,334,155 (3K tokens)
- sum(1..2000) = 2,001,000 (120K tokens)
- 8! = 40,320 (native MUL)
- collatz(27) = 111 steps (9.9K tokens)
- collatz(97) = 118 steps
- prime(1009) = 1 (2.3K tokens)
- pow(2,16) = 65,536 (native MUL)
- gcd(99991, 99989) = 1 (32-bit CONST)

### Failing (byte 2+ MUL)
- 10! = 3,628,800 (intermediate MUL > 65535)
- collatz(871) = 178 (sequence reaches 190996)
- pow(2,17+) (products > 65535)
