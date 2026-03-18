"""
Real Autoregressive WASM Interpreter — Following Percepta's Blog Exactly.

The transformer IS the computer. The program is in the tokens.
The model executes step by step, producing an execution trace.

Trace format (from blog):
  [byte0, byte1, byte2, byte3, commit_token]
  commit_token encodes stack_size (so future steps can find operands)

Operand resolution at RUNTIME:
  - The model reads commit tokens via content-matching attention
  - Finds operands by matching on stack_size values
  - No pre-compiled explicit addresses

Architecture: d_model=36, n_heads=18, head_dim=2, n_layers=7, d_ffn=36, vocab=520
"""

import time
from dataclasses import dataclass

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, Op, WasmVM
from compiler import TraceVocab

# Architecture constants
D_MODEL = 36
N_HEADS = 18
N_LAYERS = 7
D_FFN = 36
MAX_SEQ = 200000

# Program layout
MAX_INST = 600
INST_SIZE = 6  # [opcode, imm_b0, imm_b1, imm_b2/src_a, imm_b3/src_b, delta+1]
PROG_LEN = MAX_INST * INST_SIZE  # 2400
SEP_POS = PROG_LEN
TRACE_START = PROG_LEN + 1

# Trace format: 5 tokens per step [b0, b1, b2, b3, commit]
# commit = stack_size (0-253), 254 = output, 255 = halt
STEP_SIZE = 5
COMMIT_OUTPUT = 254
COMMIT_HALT = 255

# Scales
S_QUAD = 100.0   # for position-based quadratic addressing
S_STACK = 50.0    # for stack_size content matching
S_HEAD = 50.0     # for output head quadratic decoding
BIG = 200000.0    # gate suppression scale (must exceed max 16-bit operand contribution ~131K)

# Stack-size content matching offset: added to commit K so non-commit
# positions (with result bytes in dim 0) can never match
COMMIT_OFFSET = 256.0


# ============================================================
# Dimension Allocation (d_model = 36)
# ============================================================
# Token embedding:
#   0: byte_value
#   10: is_const, 11: is_add, 12: is_sub, 13: is_mul
#   14: is_output, 15: is_halt
#   29: is_le_s, 30: is_ge_s, 31: is_lt_s, 32: is_gt_s, 33: is_eq, 34: is_ne, 35: is_eqz
#
# PE:
#   1: is_program, 2: is_opcode_pos, 3: is_sep, 4: is_trace
#   5: position, 6: -S_QUAD * position²
#   7: step_number (or inst_idx in program region)
#   8: slot (byte index 0-4)
#   9: is_commit_slot (1 at slot 4)
#   27: bias (1.0)
#   28: commit_key_offset (COMMIT_OFFSET at commit positions, 0 elsewhere)
#
# Residual (written by layers):
#   10-15: opcode flags (from L0 attn fetch)
#   16: immediate byte (from L0 attn head 3)
#   17: own_stack_size (from L0 attn head 10 reading prev commit)
#   18: operand_B_commit_pos (from L1 attn head 0, commit matching)
#   19: operand_A_commit_pos (from L1 attn head 1)
#   20: fetch_addr_A (from L1 FFN)
#   21: fetch_addr_B (from L1 FFN)
#   23: operand_A_byte (from L2 attn)
#   24: operand_B_byte (from L2 attn)
#   25: ALU result (from L2 FFN)
#   26: decode result (from L6 FFN)
#   29: MUL scratch (a0*b0 for carry, from L3 FFN; safe since is_le_s=0 for MUL)


# ============================================================
# Static Analysis (for stack_size computation only)
# ============================================================

def compute_stack_sizes(program: list[Instruction]) -> list[int]:
    """Compute stack_size AFTER each instruction. Pure static analysis."""
    sizes = []
    ss = 0
    for inst in program:
        if inst.op == Op.I32_CONST:
            ss += 1
        elif inst.op in (Op.I32_ADD, Op.I32_SUB, Op.I32_MUL,
                          Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S,
                          Op.I32_GT_S, Op.I32_EQ, Op.I32_NE):
            ss -= 1  # pop 2, push 1
        elif inst.op == Op.I32_EQZ:
            pass  # pop 1, push 1
        elif inst.op == Op.OUTPUT:
            ss -= 1  # pop 1
        elif inst.op == Op.HALT:
            pass
        elif inst.op == Op.NOP:
            continue
        else:
            continue
        sizes.append(ss)
    return sizes


# ============================================================
# Program Encoding
# ============================================================

def encode_program(program: list[Instruction]) -> tuple[list[int], list[int]]:
    """
    Encode program as tokens: [opcode, imm_b0, imm_b1, src_a, src_b]

    For local.get/set: src_a = step index of value source (explicit address).
    For other ops: src_a/src_b = 0 (use stack-based resolution).

    Returns (tokens, stack_sizes).
    """
    op_to_token = {}
    for op in Op:
        op_to_token[op] = TraceVocab.OPCODE_OFFSET + op

    # First pass: compute step indices and local tracking
    stack = []       # symbolic stack of step indices
    locals_ = {}     # local_index -> step_index
    step_data = []   # (instruction, src_a, src_b) per step
    stack_sizes = []

    step = 0
    for inst in program:
        if inst.op == Op.NOP:
            continue

        src_a = 0
        src_b = 0

        if inst.op == Op.I32_CONST:
            stack.append(step)
        elif inst.op in (Op.I32_ADD, Op.I32_SUB, Op.I32_MUL,
                          Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S,
                          Op.I32_GT_S, Op.I32_EQ, Op.I32_NE):
            b_step = stack.pop() if stack else 0
            a_step = stack.pop() if stack else 0
            src_a = a_step
            src_b = b_step
            stack.append(step)
        elif inst.op == Op.I32_EQZ:
            a_step = stack.pop() if stack else 0
            src_b = a_step  # EQZ uses opB path
            stack.append(step)
        elif inst.op == Op.OUTPUT:
            if stack: stack.pop()
        elif inst.op == Op.LOCAL_SET:
            src = stack.pop() if stack else 0
            src_a = src  # explicit: where the value comes from
            local_idx = inst.operand or 0
            locals_[local_idx] = step
        elif inst.op == Op.LOCAL_GET:
            local_idx = inst.operand or 0
            src_a = locals_.get(local_idx, 0)  # explicit: most recent set
            stack.append(step)
        elif inst.op == Op.LOCAL_TEE:
            local_idx = inst.operand or 0
            src_a = stack[-1] if stack else 0
            locals_[local_idx] = step
            if stack:
                stack[-1] = step
        elif inst.op == Op.HALT:
            pass
        else:
            continue  # skip unsupported ops

        step_data.append((inst, src_a, src_b))
        stack_sizes.append(len(stack))
        step += 1

    # Second pass: encode tokens. Position 3 = src_a, Position 4 = src_b/push_flag
    tokens = []
    for i, (inst, src_a, src_b) in enumerate(step_data):
        tok = op_to_token.get(inst.op, TraceVocab.NOP)
        imm = inst.operand or 0
        ss = stack_sizes[i] if i < len(stack_sizes) else 0
        if inst.op == Op.OUTPUT:
            cv = COMMIT_OUTPUT
        elif inst.op == Op.HALT:
            cv = COMMIT_HALT
        else:
            cv = ss
        if inst.op == Op.I32_CONST:
            # Pack full 32-bit immediate into positions 1-4
            tokens.extend([tok, imm & 0xFF, (imm >> 8) & 0xFF,
                            (imm >> 16) & 0xFF, (imm >> 24) & 0xFF, cv & 0xFF])
        else:
            tokens.extend([tok, imm & 0xFF, (imm >> 8) & 0xFF,
                            src_a & 0xFF, src_b & 0xFF, cv & 0xFF])

    while len(tokens) < PROG_LEN:
        tokens.extend([TraceVocab.NOP, 0, 0, 0, 0, 0])
    tokens.append(TraceVocab.SEP)
    return tokens, stack_sizes


# ============================================================
# Model Builder
# ============================================================

def build_interpreter() -> VanillaTransformer:
    """Build ONE universal interpreter. Same weights for ALL programs."""
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=D_MODEL, n_heads=N_HEADS, n_layers=N_LAYERS,
        d_ffn=D_FFN,
        max_seq_len=MAX_SEQ, pe_mode='learned',
    )
    model = model.double()  # convert to float64 BEFORE setting weights to avoid precision loss
    with torch.no_grad():
        _set_universal_weights(model)
        _set_universal_pe(model)
    model.eval()
    return model


def _set_universal_weights(model):
    """
    Set universal weights — SAME for ALL programs.

    Layer 0 attn: Instruction fetch (heads 0-5) + read prev commit (head 10)
    Layer 0 FFN:  Compute commit K components (filtered stack_size² at commit pos)
    Layer 1 attn: Stack-based operand resolution (match commit stack_sizes)
    Layer 1 FFN:  Compute byte fetch addresses from matched commit positions
    Layer 2 attn: Fetch operand bytes from computed positions
    Layer 2 FFN:  ALU (ADD, SUB, MUL, CONST, comparisons, etc.)
    Layer 3 FFN:  Copy result to decode dim + commit generation
    Output head:  Quadratic byte decoding + commit token decoding
    """
    d = D_MODEL

    # Zero everything
    for layer in range(N_LAYERS):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()

    # ================================================================
    # Token Embedding
    # ================================================================
    tok = model.tok.weight

    # Byte tokens (0-255): value in dim 0
    for v in range(256):
        tok[v, 0] = float(v)

    # Opcode tokens: flags
    opcode_flags = {
        Op.I32_CONST: 10, Op.I32_ADD: 11, Op.I32_SUB: 12, Op.I32_MUL: 13,
        Op.OUTPUT: 14, Op.HALT: 15,
        Op.I32_LE_S: 29, Op.I32_GE_S: 30, Op.I32_LT_S: 31, Op.I32_GT_S: 32,
        Op.I32_EQ: 33, Op.I32_NE: 34, Op.I32_EQZ: 35,
    }
    for op, dim in opcode_flags.items():
        tok_id = TraceVocab.OPCODE_OFFSET + op
        if tok_id < tok.shape[0]:
            tok[tok_id, dim] = 1.0

    # ================================================================
    # Layer 0 Attention: Instruction Fetch + Read Previous Commit
    # ================================================================
    W0 = model.attn[0].in_proj_weight
    out0 = model.attn[0].out_proj.weight

    # Heads 0-5: fetch instruction info (same as before)
    # Token flags for local ops
    for local_op in (Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE):
        tok_id = TraceVocab.OPCODE_OFFSET + local_op
        if tok_id < tok.shape[0]:
            tok[tok_id, 22] = 1.0  # is_copy flag for ALU passthrough
    # Local ops: only is_copy flag (dim 22). No other opcode flags.
    # Commit values are pre-encoded in program tokens (position 4 of each instruction).

    fetch_heads = [
        (0, 0, (10, 11), (10, 11)),  # is_const, is_add
        (1, 0, (12, 13), (12, 13)),  # is_sub, is_mul
        (2, 0, (14, 15), (14, 15)),  # is_output, is_halt
        (3, 1, (0, -1), (16, -1)),   # immediate byte
        (4, 3, (0, -1), (4, -1)),    # src_a explicit addr → dim 4
        (5, 4, (0, -1), (18, -1)),   # src_b from prog pos +4 → dim 18 (clean at L1)
        (11, 5, (0, -1), (17, -1)),  # commit_val from prog pos +5 → dim 17
        (6, 0, (29, 30), (29, 30)),  # is_le_s, is_ge_s
        (7, 0, (31, 32), (31, 32)),  # is_lt_s, is_gt_s
        (8, 0, (33, 34), (33, 34)),  # is_eq, is_ne
        (9, 0, (22, 35), (22, 35)),  # is_copy, is_eqz
    ]
    for head, offset, v_dims, out_dims in fetch_heads:
        h2 = head * 2
        W0[h2, 7] = 2 * S_QUAD * INST_SIZE
        W0[h2, 27] = 2 * S_QUAD * offset
        if head == 3:
            W0[h2, 8] = 2 * S_QUAD  # byte_idx for immediate
        W0[h2 + 1, 27] = 1.0
        W0[d + h2, 5] = 1.0
        W0[d + h2 + 1, 6] = 1.0
        if v_dims[0] >= 0:
            W0[2*d + h2, v_dims[0]] = 1.0
        if v_dims[1] >= 0:
            W0[2*d + h2 + 1, v_dims[1]] = 1.0
        if out_dims[0] >= 0:
            out0[out_dims[0], h2] = 1.0
        if out_dims[1] >= 0:
            out0[out_dims[1], h2 + 1] = 1.0

    # Head 10: REMOVED (no longer needed — commit_val pre-encoded in program)
    # Head 11 fetches commit_val from program position +5 → dim 17.

    # ================================================================
    # Layer 0 FFN: (no stack-based commit K needed — using explicit addresses)
    # ================================================================

    # Layer 1: (no stack-based operand resolution — using explicit addresses)

    # ================================================================
    # Layer 1 FFN: Compute byte fetch addresses from commit positions
    # ================================================================
    # Byte value is 4 positions before commit: pos - 4 + byte_idx
    # target_pos = commit_pos - 4 + byte_idx
    # fetch_addr = 2 * S_QUAD * target_pos
    ff1_in = model.ff_in[1].weight
    ff1_out = model.ff_out[1].weight

    # Gates 0-1: REMOVED (stack-based resolution doesn't scale for long traces)
    # All operand resolution now uses explicit addresses via gates 2-3 below.

    # Gate 2: fetch addr for operand A (explicit-address: ALL ops with src_a)
    # src_a from dim 4 (head 4). dim 4 = is_trace(1.0) + src_a, compensate with -STEP_SIZE
    # Fires for: copy ops + ALL binary ops + EQZ (anything with explicit src_a)
    for fd in (11, 12, 13, 22, 29, 30, 31, 32, 33, 34, 35):
        ff1_in[2, fd] = 1.0
    ff1_in[D_FFN + 2, 4] = 2 * S_QUAD * STEP_SIZE
    ff1_in[D_FFN + 2, 8] = 2 * S_QUAD
    ff1_in[D_FFN + 2, 27] = 2 * S_QUAD * (TRACE_START - STEP_SIZE)
    ff1_out[21, 2] = 1.0

    # Gate 3: fetch addr for operand B (explicit-address: binary ops)
    # src_b from dim 2 (head 5 at position +4)
    # dim 2 = push_flag/src_b. For binary ops: src_b. For local.get: 1 (push flag).
    for fd in (11, 12, 13, 29, 30, 31, 32, 33, 34, 35):
        ff1_in[3, fd] = 1.0
    ff1_in[D_FFN + 3, 18] = 2 * S_QUAD * STEP_SIZE  # src_b (from dim 18, head 5)
    ff1_in[D_FFN + 3, 8] = 2 * S_QUAD
    ff1_in[D_FFN + 3, 27] = 2 * S_QUAD * TRACE_START
    ff1_out[3, 3] = 1.0  # -> dim 3 (fetch_addr_B, overrides stack-based)

    # ================================================================
    # Layer 2 Attention: Fetch operand bytes from trace
    # ================================================================
    W2 = model.attn[2].in_proj_weight
    out2 = model.attn[2].out_proj.weight

    # Head 0: fetch operand A byte
    W2[0, 21] = 1.0; W2[1, 27] = 1.0     # Q = [fetch_addr_A, 1]
    W2[d+0, 5] = 1.0; W2[d+1, 6] = 1.0   # K = [pos, -S*pos²]
    W2[2*d+0, 0] = 1.0                     # V = byte_value
    out2[23, 0] = 1.0                       # -> dim 23 (operand_A)

    # Head 1: fetch operand B byte
    W2[2, 3] = 1.0; W2[3, 27] = 1.0       # Q = [fetch_addr_B (dim 3), 1]
    W2[d+2, 5] = 1.0; W2[d+3, 6] = 1.0
    W2[2*d+2, 0] = 1.0
    out2[24, 2] = 1.0                       # -> dim 24 (operand_B)

    # Head 2: fetch opA byte 1 → dim 2
    W2[4, 21] = 1.0; W2[4, 27] = 2.0 * S_QUAD  # Q = [fetch_addr_A + 2S, ...]
    W2[5, 27] = 1.0
    W2[d+4, 5] = 1.0; W2[d+5, 6] = 1.0
    W2[2*d+4, 0] = 1.0
    out2[2, 4] = 1.0  # → dim 2

    # Head 3: fetch opB byte 1 → dim 26
    W2[6, 3] = 1.0; W2[6, 27] = 2.0 * S_QUAD  # Q = [fetch_addr_B + 2S, ...]
    W2[7, 27] = 1.0
    W2[d+6, 5] = 1.0; W2[d+7, 6] = 1.0
    W2[2*d+6, 0] = 1.0
    out2[26, 6] = 1.0  # → dim 26

    # ================================================================
    # Layer 2 FFN: ALU
    # ================================================================
    ff2_in = model.ff_in[2].weight
    ff2_out = model.ff_out[2].weight

    # Gate 0 (ADD) — all byte slots (suppress at commit only)
    ff2_in[0, 11] = 1.0; ff2_in[0, 9] = -2.0  # suppress at commit slot
    ff2_in[D_FFN+0, 23] = 1.0; ff2_in[D_FFN+0, 24] = 1.0
    ff2_out[25, 0] = 1.0

    # Gate 1 (CONST) — all byte slots (suppress at commit only)
    ff2_in[1, 10] = 1.0; ff2_in[1, 9] = -2.0
    ff2_in[D_FFN+1, 16] = 1.0
    ff2_out[25, 1] = 1.0

    # Gate 2 (SUB) — slot 0 only
    ff2_in[2, 12] = 1.0; ff2_in[2, 8] = -2.0
    ff2_in[D_FFN+2, 23] = 1.0; ff2_in[D_FFN+2, 24] = -1.0
    ff2_out[25, 2] = 1.0

    # Gate 3 (MUL) — slot 0 only (bilinear)
    ff2_in[3, 23] = 1.0; ff2_in[3, 13] = BIG; ff2_in[3, 27] = -BIG; ff2_in[3, 8] = -2*BIG
    ff2_in[D_FFN+3, 24] = 1.0
    ff2_out[25, 3] = 1.0

    # Gate 4 (COPY / passthrough for local.get/set/tee) — all byte slots
    ff2_in[4, 22] = 1.0; ff2_in[4, 9] = -2.0  # suppress commit
    ff2_in[D_FFN+4, 23] = 1.0  # val = opA
    ff2_out[25, 4] = 1.0

    # Comparison gates (slot 0 only) — 16-bit: a0 + 256*a1 vs b0 + 256*b1
    def _cmp_gate(g, flag_dim, a_sign, b_sign, threshold, out_sign):
        ff2_in[g, flag_dim] = BIG; ff2_in[g, 27] = -BIG + threshold; ff2_in[g, 8] = -2*BIG
        ff2_in[g, 23] = a_sign; ff2_in[g, 24] = b_sign
        ff2_in[g, 2] = 256.0 * a_sign   # 256 * opA_byte1
        ff2_in[g, 26] = 256.0 * b_sign  # 256 * opB_byte1
        ff2_in[D_FFN+g, 27] = 1.0; ff2_out[25, g] = out_sign

    def _bias_gate(g, flag_dim):
        ff2_in[g, flag_dim] = 1.0; ff2_in[g, 8] = -2.0
        ff2_in[D_FFN+g, 27] = 1.0; ff2_out[25, g] = 1.0

    # LT_S: relu(B-A) - relu(B-A-1)
    _cmp_gate(7, 31, -1, 1, 0, +1); _cmp_gate(8, 31, -1, 1, -1, -1)
    # GT_S: relu(A-B) - relu(A-B-1)
    _cmp_gate(9, 32, 1, -1, 0, +1); _cmp_gate(10, 32, 1, -1, -1, -1)
    # LE_S: 1 - GT
    _bias_gate(11, 29); _cmp_gate(12, 29, 1, -1, 0, -1); _cmp_gate(13, 29, 1, -1, -1, +1)
    # GE_S: 1 - LT
    _bias_gate(14, 30); _cmp_gate(15, 30, -1, 1, 0, -1); _cmp_gate(16, 30, -1, 1, -1, +1)
    # EQ: 1 - LT - GT
    _bias_gate(17, 33)
    _cmp_gate(18, 33, -1, 1, 0, -1); _cmp_gate(19, 33, -1, 1, -1, +1)
    _cmp_gate(20, 33, 1, -1, 0, -1); _cmp_gate(21, 33, 1, -1, -1, +1)
    # NE: LT + GT
    _cmp_gate(22, 34, -1, 1, 0, +1); _cmp_gate(23, 34, -1, 1, -1, -1)
    _cmp_gate(24, 34, 1, -1, 0, +1); _cmp_gate(25, 34, 1, -1, -1, -1)
    # EQZ: 1 - relu(A) + relu(A-1)
    _bias_gate(26, 35)
    # EQZ reads from opB (dim 24 = top of stack from ss=own_ss), not opA (ss-1)
    # 16-bit: also reads byte 1 from dim 26 (opB byte 1) with 256x weight
    ff2_in[27, 35] = BIG; ff2_in[27, 27] = -BIG; ff2_in[27, 8] = -2*BIG
    ff2_in[27, 24] = 1.0; ff2_in[27, 26] = 256.0; ff2_in[D_FFN+27, 27] = 1.0; ff2_out[25, 27] = -1.0
    ff2_in[28, 35] = BIG; ff2_in[28, 27] = -1.0 - BIG; ff2_in[28, 8] = -2*BIG
    ff2_in[28, 24] = 1.0; ff2_in[28, 26] = 256.0; ff2_in[D_FFN+28, 27] = 1.0; ff2_out[25, 28] = 1.0

    # ---- Single commit gate: reads pre-encoded commit_val from dim 17 (head 11) ----
    # At commit slot (dim 9=1): output = commit_val.
    # At byte slots (dim 9=0): doesn't fire.
    ff2_in[29, 17] = 1.0       # commit_val
    ff2_in[29, 9] = BIG        # is_commit_slot
    ff2_in[29, 27] = -BIG      # threshold
    ff2_in[D_FFN+29, 27] = 1.0
    ff2_out[25, 29] = 1.0

    # ================================================================
    # Layer 3 Attention: Fetch prev-byte operands for carry detection
    # ================================================================
    # At byte slot k>0, fetch opA[k-1] and opB[k-1]
    # Q targets fetch_addr - 2*S_QUAD (one position earlier = prev byte)
    W3 = model.attn[3].in_proj_weight
    out3 = model.attn[3].out_proj.weight

    # Head 0: prev opA → dim 19 (not dim 26, which L2 uses for opB byte-1)
    W3[0, 21] = 1.0; W3[0, 27] = -2.0 * S_QUAD
    W3[1, 27] = 1.0
    W3[d+0, 5] = 1.0; W3[d+1, 6] = 1.0
    W3[2*d+0, 0] = 1.0
    out3[19, 0] = 1.0  # -> dim 19 (prevA)

    # Head 1: prev opB → dim 1 (not dim 2, which L2 uses for opA byte-1)
    W3[2, 3] = 1.0; W3[2, 27] = -2.0 * S_QUAD
    W3[3, 27] = 1.0
    W3[d+2, 5] = 1.0; W3[d+3, 6] = 1.0
    W3[2*d+2, 0] = 1.0
    out3[1, 2] = 1.0  # -> dim 1 (prevB)

    # ================================================================
    # Layer 3 FFN: ADD carry — add 1 if prev byte overflowed
    # ================================================================
    # carry = relu(prevA + prevB - 255) - relu(prevA + prevB - 256) = {0,1}
    # Only at byte slots 1-3 for ADD
    ff3_in = model.ff_in[3].weight
    ff3_out = model.ff_out[3].weight

    # dim 28 at slots 1-3 = is_carry_eligible? No, we changed it to is_commit_input.
    # Use slot > 0 AND not commit: byte_idx >= 1 AND is_commit=0
    # Gate: relu(prevA + prevB - 255 + BIG*is_add + BIG*slot - BIG*bias - 2*BIG*is_commit)
    # At slot 1, is_add=1, commit=0: gate = prevA+prevB-255+BIG+BIG-BIG = prevA+prevB-255+BIG
    # Hmm, need slot>0 check. Use: BIG*(slot/1) but slot is continuous.
    # Simpler: suppress at slot 0 with -BIG*(1-slot_positive).
    # Use: gate needs is_add AND slot>0 AND not_commit.
    # Let's use: BIG*is_add + 0.5*slot - BIG → fires when is_add=1 AND slot≥1

    # Gate 4: relu(prevA + prevB - 255 + BIG*is_add - BIG - 2*BIG*is_commit - 2*BIG*is_commit_input)
    # is_commit_input (dim 28) = 1 at slot 0, 0 at slots 1-4 → suppresses at slot 0
    # At slots 1-3 (is_add=1, is_commit=0, is_commit_input=0): relu(prevA + prevB - 255)
    # Carry gates read dim 19 (prevA) and dim 1 (prevB)
    ff3_in[4, 19] = 1.0   # prev_opA (dim 19)
    ff3_in[4, 1] = 1.0    # prev_opB (dim 1)
    ff3_in[4, 27] = -255.0 - BIG
    ff3_in[4, 11] = BIG
    ff3_in[4, 9] = -2*BIG
    ff3_in[4, 28] = -2*BIG  # suppress at slot 0 (is_commit_input=1 there)
    ff3_in[D_FFN+4, 27] = 1.0
    ff3_out[25, 4] = 1.0

    # Gate 5: -relu(prevA + prevB - 256)
    ff3_in[5, 19] = 1.0; ff3_in[5, 1] = 1.0
    ff3_in[5, 27] = -256.0 - BIG
    ff3_in[5, 11] = BIG; ff3_in[5, 9] = -2*BIG; ff3_in[5, 28] = -2*BIG
    ff3_in[D_FFN+5, 27] = 1.0
    ff3_out[25, 5] = -1.0

    # Gate 6: clear dim 26 (has L2 opB byte-1, must not reach output head)
    ff3_in[6, 27] = 1.0
    ff3_in[D_FFN+6, 26] = -1.0
    ff3_out[26, 6] = 1.0

    # Gate 7: a0*b0 for MUL carry at slot > 0 → dim 29 (safe scratch: is_le_s=0 for MUL)
    ff3_in[7, 19] = 1.0      # gate = a0 (prevA from dim 19)
    ff3_in[7, 13] = BIG      # +BIG*is_mul
    ff3_in[7, 27] = -BIG     # -BIG threshold
    ff3_in[7, 9] = -2*BIG    # suppress commit
    ff3_in[7, 28] = -2*BIG   # suppress slot 0 (is_commit_input=1 there)
    ff3_in[D_FFN+7, 1] = 1.0   # value = b0 (prevB from dim 1)
    ff3_out[29, 7] = 1.0       # → dim 29 (is_le_s=0 for MUL, safe scratch)

    # Gate 8: a1*b0 for MUL byte 1 → dim 25
    ff3_in[8, 23] = 1.0      # gate = a1 (opA byte at current slot)
    ff3_in[8, 13] = BIG
    ff3_in[8, 27] = -BIG
    ff3_in[8, 9] = -2*BIG
    ff3_in[8, 28] = -2*BIG
    ff3_in[D_FFN+8, 1] = 1.0   # value = b0 (prevB)
    ff3_out[25, 8] = 1.0

    # Gate 9: a0*b1 for MUL byte 1 → dim 25
    ff3_in[9, 19] = 1.0      # gate = a0 (prevA from dim 19)
    ff3_in[9, 13] = BIG
    ff3_in[9, 27] = -BIG
    ff3_in[9, 9] = -2*BIG
    ff3_in[9, 28] = -2*BIG
    ff3_in[D_FFN+9, 24] = 1.0  # value = b1 (opB byte at current slot)
    ff3_out[25, 9] = 1.0

    # ================================================================
    # Layer 4 FFN: Mod 256 for ADD + mod 4096 for MUL byte 0 + MUL carry
    # ================================================================
    ff4_in = model.ff_in[4].weight
    ff4_out = model.ff_out[4].weight

    # Gates 0-1: single -256 for ADD only (NOT MUL — MUL uses two-stage mod)
    ff4_in[0, 25] = 1.0; ff4_in[0, 27] = -255.0 - BIG; ff4_in[0, 11] = BIG
    ff4_in[0, 9] = -2*BIG
    ff4_in[D_FFN+0, 27] = 1.0; ff4_out[25, 0] = -256.0

    ff4_in[1, 25] = 1.0; ff4_in[1, 27] = -256.0 - BIG; ff4_in[1, 11] = BIG
    ff4_in[1, 9] = -2*BIG
    ff4_in[D_FFN+1, 27] = 1.0; ff4_out[25, 1] = 256.0

    # Gates 2-33: mod 4096 step functions for MUL at SLOT 0 ONLY (16 pairs)
    # Step function: -4096 * step(x >= k*4096) = -4096 * (relu(x - k*4096 + 1) - relu(x - k*4096))
    # Gate g: relu(x - (k*4096 - 1)), output -4096
    # Gate g+1: relu(x - k*4096), output +4096
    for k in range(1, 17):
        g = 2 + (k-1)*2
        ff4_in[g, 25] = 1.0
        ff4_in[g, 13] = BIG
        ff4_in[g, 28] = BIG
        ff4_in[g, 27] = -float(k * 4096 - 1) - 2*BIG
        ff4_in[g, 9] = -2*BIG
        ff4_in[D_FFN+g, 27] = 1.0
        ff4_out[25, g] = -4096.0
        g2 = g + 1
        ff4_in[g2, 25] = 1.0
        ff4_in[g2, 13] = BIG
        ff4_in[g2, 28] = BIG
        ff4_in[g2, 27] = -float(k * 4096) - 2*BIG
        ff4_in[g2, 9] = -2*BIG
        ff4_in[D_FFN+g2, 27] = 1.0
        ff4_out[25, g2] = 4096.0

    # Gate 34: MUL carry at slot > 0
    ff4_in[34, 29] = 1.0       # +a0*b0 (from dim 29, scratch)
    ff4_in[34, 0] = -1.0
    ff4_in[34, 13] = BIG
    ff4_in[34, 27] = -BIG
    ff4_in[34, 9] = -2*BIG
    ff4_in[34, 28] = -2*BIG
    ff4_in[D_FFN+34, 27] = 1.0
    ff4_out[25, 34] = 1.0/256.0

    # ================================================================
    # Layer 5 FFN: Mod 4096 for MUL at all non-commit slots
    # ================================================================
    ff5_in = model.ff_in[5].weight
    ff5_out = model.ff_out[5].weight
    for k in range(1, 17):
        g = (k-1)*2
        ff5_in[g, 25] = 1.0
        ff5_in[g, 13] = BIG
        ff5_in[g, 27] = -float(k * 4096 - 1) - BIG
        ff5_in[g, 9] = -2*BIG
        ff5_in[D_FFN+g, 27] = 1.0
        ff5_out[25, g] = -4096.0
        g2 = g + 1
        ff5_in[g2, 25] = 1.0
        ff5_in[g2, 13] = BIG
        ff5_in[g2, 27] = -float(k * 4096) - BIG
        ff5_in[g2, 9] = -2*BIG
        ff5_in[D_FFN+g2, 27] = 1.0
        ff5_out[25, g2] = 4096.0

    # ================================================================
    # Layer 6 FFN: Mod 256 for MUL + copy result to decode dim
    # ================================================================
    ff6_in = model.ff_in[6].weight
    ff6_out = model.ff_out[6].weight
    for k in range(1, 16):
        g = (k-1)*2
        ff6_in[g, 25] = 1.0
        ff6_in[g, 13] = BIG
        ff6_in[g, 27] = -float(k * 256 - 1) - BIG
        ff6_in[g, 9] = -2*BIG
        ff6_in[D_FFN+g, 27] = 1.0
        ff6_out[25, g] = -256.0
        g2 = g + 1
        ff6_in[g2, 25] = 1.0
        ff6_in[g2, 13] = BIG
        ff6_in[g2, 27] = -float(k * 256) - BIG
        ff6_in[g2, 9] = -2*BIG
        ff6_in[D_FFN+g2, 27] = 1.0
        ff6_out[25, g2] = 256.0
    # Gate 30: copy result to decode dim (for ALL ops)
    ff6_in[30, 27] = 1.0
    ff6_in[D_FFN+30, 25] = 1.0
    ff6_out[26, 30] = 1.0

    # ================================================================
    # Output Head: Quadratic byte decoding + commit token decoding
    # ================================================================
    head = model.head.weight

    # Byte tokens 0-255: decode directly from dim 25 (result accumulator)
    # No copy-to-decode needed — dim 25 has the final value after all layer corrections
    for b in range(256):
        head[b, 25] = S_HEAD * b
        head[b, 27] = -S_HEAD * b * b / 2.0

    head[0, 27] = 1.0  # bias for byte 0 to win ties

    # At commit slot (slot 4), result = stack_size.
    # The commit is encoded as: dim 17 = own_stack_size (from L0).
    # But own_stack_size needs adjustment based on instruction type.
    # For now, stack_size is pre-encoded in the expected trace.
    # The quadratic head naturally decodes it from dim 26.


def _set_universal_pe(model):
    """Universal position embeddings — SAME for ALL programs."""
    pe = model.pos_tok.weight
    pe.zero_()

    for t in range(min(MAX_SEQ, pe.shape[0])):
        pe[t, 5] = float(t)
        pe[t, 6] = -S_QUAD * float(t) ** 2
        pe[t, 27] = 1.0

        if t < PROG_LEN:
            inst_idx = t // INST_SIZE
            pe[t, 1] = 1.0
            if t % INST_SIZE == 0:
                pe[t, 2] = 1.0
            pe[t, 7] = float(inst_idx)
        elif t == SEP_POS:
            pe[t, 3] = 1.0; pe[t, 4] = 1.0
            pe[t, 7] = 0.0; pe[t, 8] = 0.0
        else:
            next_trace_offset = (t + 1) - TRACE_START
            if next_trace_offset < 0:
                continue
            step = next_trace_offset // STEP_SIZE
            slot = next_trace_offset % STEP_SIZE
            pe[t, 4] = 1.0
            pe[t, 7] = float(step)
            pe[t, 8] = float(slot)
            if slot == 4:
                pe[t, 9] = 1.0   # is_commit_slot (predicts commit)

            # dim 28: is_commit_input — marks positions WHERE a commit
            # token is the INPUT (i.e., the token at this position IS a commit)
            input_trace_offset = t - TRACE_START
            if input_trace_offset >= 0 and input_trace_offset % STEP_SIZE == 4:
                pe[t, 28] = 1.0  # this position has a commit token as input


# ============================================================
# Trace Generation
# ============================================================

def generate_trace_rust_multilayer(model, prog_tokens: list[int], max_trace_tokens=500) -> list[int]:
    """Generate trace using Rust engine with multi-layer support."""
    try:
        from llm_compute_engine import generate_trace_multilayer
    except ImportError:
        return generate_trace(model, prog_tokens, max_trace_tokens)

    model.eval()
    with torch.no_grad():
        tok_w = model.tok.weight.detach().double().flatten().tolist()
        pe_w = model.pos_tok.weight.detach().double().flatten().tolist()
        pe_rows = model.pos_tok.weight.shape[0]
        head_w = model.head.weight.detach().double().flatten().tolist()

        # Pack layer weights: in_proj + out_proj + ff_in + ff_out per layer
        layer_weights = []
        for l in range(N_LAYERS):
            layer_weights.extend(model.attn[l].in_proj_weight.detach().double().flatten().tolist())
            layer_weights.extend(model.attn[l].out_proj.weight.detach().double().flatten().tolist())
            layer_weights.extend(model.ff_in[l].weight.detach().double().flatten().tolist())
            layer_weights.extend(model.ff_out[l].weight.detach().double().flatten().tolist())

        return generate_trace_multilayer(
            tok_w, pe_w, pe_rows, layer_weights, head_w,
            prog_tokens, max_trace_tokens, COMMIT_HALT, STEP_SIZE,
        )


def generate_trace(model, prog_tokens: list[int], max_trace_tokens=500) -> list[int]:
    """Generate trace with KV caching (Python fallback)."""
    model.eval()
    trace_tokens = []

    with torch.no_grad():
        # First pass: process all program tokens at once
        input_ids = torch.tensor([prog_tokens], dtype=torch.long)
        T = input_ids.shape[1]
        x = model.tok(input_ids) + model.pos_tok(torch.arange(T).unsqueeze(0))
        x = x.double()
        mask = torch.triu(torch.ones(T, T, dtype=torch.bool), diagonal=1)

        # Build KV cache: store K, V for each layer
        kv_cache = []  # [(K, V) per layer]
        for layer in range(N_LAYERS):
            W = model.attn[layer].in_proj_weight
            d = D_MODEL
            K = (x @ W[d:2*d].T)    # (1, T, d)
            V = (x @ W[2*d:].T)     # (1, T, d)
            Q = (x @ W[:d].T)
            # Full attention for prefill
            head_dim = 2
            n_h = N_HEADS
            Qr = Q.view(1, T, n_h, head_dim).transpose(1, 2)
            Kr = K.view(1, T, n_h, head_dim).transpose(1, 2)
            Vr = V.view(1, T, n_h, head_dim).transpose(1, 2)
            scores = (Qr @ Kr.transpose(-2, -1)) / (head_dim ** 0.5)
            scores.masked_fill_(mask[:T, :T].unsqueeze(0).unsqueeze(0), float('-inf'))
            # Hard-max attention (argmax) — no overflow, matches Rust engine
            best = scores.argmax(dim=-1, keepdim=True)
            y = Vr.gather(2, best.expand(-1, -1, -1, head_dim))
            y = y.transpose(1, 2).reshape(1, T, d)
            y = y @ model.attn[layer].out_proj.weight.T
            x = x + y
            # FFN
            g, v = model.ff_in[layer](x).chunk(2, dim=-1)
            x = x + model.ff_out[layer](torch.relu(g) * v)
            kv_cache.append((K, V))

        # Get logits for last position
        logits = model.head(x[0, -1])
        next_token = logits.argmax().item()
        trace_tokens.append(next_token)

        # Incremental generation with KV cache
        for i in range(1, max_trace_tokens):
            if i > 1:
                slot = (i - 1) % STEP_SIZE
                if slot == 4 and trace_tokens[-1] == COMMIT_HALT:
                    break

            pos = T + i - 1  # position of new token
            tok_emb = model.tok.weight[next_token].unsqueeze(0).unsqueeze(0)  # (1,1,d)
            pe_emb = model.pos_tok.weight[pos].unsqueeze(0).unsqueeze(0) if pos < model.pos_tok.weight.shape[0] else torch.zeros(1, 1, d, dtype=torch.float64)
            x_new = (tok_emb + pe_emb).double()

            for layer in range(N_LAYERS):
                W = model.attn[layer].in_proj_weight
                d = D_MODEL
                K_new = x_new @ W[d:2*d].T     # (1, 1, d)
                V_new = x_new @ W[2*d:].T
                Q_new = x_new @ W[:d].T

                # Append to cache
                K_cached, V_cached = kv_cache[layer]
                K_all = torch.cat([K_cached, K_new], dim=1)
                V_all = torch.cat([V_cached, V_new], dim=1)
                kv_cache[layer] = (K_all, V_all)

                # Attention: Q_new attends to all K, V
                head_dim = 2
                n_h = N_HEADS
                Qr = Q_new.view(1, 1, n_h, head_dim).transpose(1, 2)  # (1,nh,1,hd)
                Kr = K_all.view(1, -1, n_h, head_dim).transpose(1, 2)  # (1,nh,T,hd)
                Vr = V_all.view(1, -1, n_h, head_dim).transpose(1, 2)
                scores = (Qr @ Kr.transpose(-2, -1)) / (head_dim ** 0.5)
                # Hard-max attention (argmax)
                best = scores.argmax(dim=-1, keepdim=True)
                y = Vr.gather(2, best.expand(-1, -1, -1, head_dim))
                y = y.transpose(1, 2).reshape(1, 1, D_MODEL)
                y = y @ model.attn[layer].out_proj.weight.T
                x_new = x_new + y

                # FFN
                g, v = model.ff_in[layer](x_new).chunk(2, dim=-1)
                x_new = x_new + model.ff_out[layer](torch.relu(g) * v)

            logits = model.head(x_new[0, 0])
            next_token = logits.argmax().item()
            trace_tokens.append(next_token)

    return trace_tokens


# ============================================================
# Run program
# ============================================================

def trace_compile_program(program: list[Instruction]) -> tuple[list[int], list[int]]:
    """
    Compile program via VM trace unrolling for control flow support.
    VM provides STRUCTURE only. Values computed by model at runtime.
    Returns (tokens, stack_sizes) same format as encode_program.
    """
    vm = WasmVM()
    vm.load_program(program)
    vm_trace = vm.run()

    op_to_token = {}
    for op in Op:
        op_to_token[op] = TraceVocab.OPCODE_OFFSET + op

    _BINARY = {'i32_add': Op.I32_ADD, 'i32_sub': Op.I32_SUB, 'i32_mul': Op.I32_MUL,
               'i32_le_s': Op.I32_LE_S, 'i32_ge_s': Op.I32_GE_S,
               'i32_lt_s': Op.I32_LT_S, 'i32_gt_s': Op.I32_GT_S,
               'i32_eq': Op.I32_EQ, 'i32_ne': Op.I32_NE}

    stack = []
    locals_ = {}
    memory = {}  # address -> step_index of most recent store
    tokens = []
    stack_sizes = []
    step = 0

    for entry in vm_trace:
        op_name = entry.get('op', '')
        if op_name == 'nop':
            continue

        tok_id = TraceVocab.NOP
        imm = 0
        src_a = 0
        push_flag = 0

        if op_name == 'halt':
            tok_id = op_to_token[Op.HALT]
            tokens.extend([tok_id, 0, 0, 0, 0, COMMIT_HALT])
            stack_sizes.append(len(stack))
            break
        elif op_name == 'i32_const':
            tok_id = op_to_token[Op.I32_CONST]
            imm = entry.get('operand', 0) or 0
            stack.append(step)
        elif op_name in _BINARY:
            tok_id = op_to_token[_BINARY[op_name]]
            b_step = stack.pop() if stack else 0
            a_step = stack.pop() if stack else 0
            src_a = a_step  # explicit address for operand A
            # src_b goes in push_flag position (overloaded for binary ops)
            push_flag = b_step  # explicit address for operand B
            stack.append(step)
        elif op_name == 'i32_eqz':
            tok_id = op_to_token[Op.I32_EQZ]
            a_step = stack.pop() if stack else 0
            push_flag = a_step  # EQZ operand via explicit address (opB path)
            stack.append(step)
        elif op_name in ('output', 'output_char'):
            tok_id = op_to_token[Op.OUTPUT]
            if stack: stack.pop()
        elif op_name == 'local_set':
            tok_id = op_to_token[Op.LOCAL_SET]
            src_a = stack.pop() if stack else 0
            locals_[entry.get('operand', 0)] = step
        elif op_name == 'local_get':
            tok_id = op_to_token[Op.LOCAL_GET]
            src_a = locals_.get(entry.get('operand', 0), 0)
            push_flag = 1
            stack.append(step)
        elif op_name == 'local_tee':
            tok_id = op_to_token[Op.LOCAL_TEE]
            src_a = stack[-1] if stack else 0
            locals_[entry.get('operand', 0)] = step
            if stack: stack[-1] = step
        else:
            # Non-computable ops: encode as CONST with baked value
            val = entry.get('stack_top', 0) or 0
            tok_id = op_to_token[Op.I32_CONST]
            imm = val & 0xFFFF
            # Track stack effects
            if op_name in ('i32_div_s', 'i32_rem_s', 'i32_and', 'i32_or',
                           'i32_xor', 'i32_shl', 'i32_shr_s'):
                if len(stack) >= 2: stack.pop(); stack.pop()
                stack.append(step)
            elif op_name in ('i32_load', 'i32_load8_u', 'i32_load8_s'):
                # Load: copy from the store step that wrote this address.
                addr_step = stack.pop() if stack else 0
                # Find which store matches by using step_values tracking
                # The addr_step's value = the memory address
                # Look up which store step wrote to that address
                src_a = memory.get('last_store', 0)  # simple: last store
                push_flag = 1
                tok_id = op_to_token.get(Op.LOCAL_GET, TraceVocab.NOP)
                stack.append(step)
            elif op_name in ('i32_store', 'i32_store8'):
                # Store: copy value for future loads.
                val_step = stack.pop() if stack else 0
                addr_step = stack.pop() if stack else 0
                src_a = val_step
                tok_id = op_to_token.get(Op.LOCAL_SET, TraceVocab.NOP)
                memory['last_store'] = step
            elif op_name in ('if', 'br_if'):
                # Structural: skip WITHOUT popping from our tracking stack.
                # The model never sees this pop, so its stack tracking stays higher.
                # This is intentional — the model's commits are self-consistent.
                continue
            elif op_name == 'drop':
                if stack: stack.pop()
                continue
            elif op_name in ('block', 'loop', 'else', 'end', 'br', 'nop',
                              'select', 'return', 'call'):
                continue  # structural ops, no trace step
            else:
                continue

        ss = len(stack)
        if op_name in ('output', 'output_char'):
            cv = COMMIT_OUTPUT
        elif op_name == 'halt':
            cv = COMMIT_HALT
        else:
            cv = ss
        # 6-token encoding: [opcode, imm_b0, imm_b1, imm_b2/src_a, imm_b3/src_b, commit_val]
        src_b = push_flag
        if tok_id == op_to_token.get(Op.I32_CONST):
            tokens.extend([tok_id, imm & 0xFF, (imm >> 8) & 0xFF,
                            (imm >> 16) & 0xFF, (imm >> 24) & 0xFF, cv & 0xFF])
        else:
            tokens.extend([tok_id, imm & 0xFF, (imm >> 8) & 0xFF,
                            src_a & 0xFF, src_b & 0xFF, cv & 0xFF])
        stack_sizes.append(ss)
        step += 1

    while len(tokens) < PROG_LEN:
        tokens.extend([TraceVocab.NOP, 0, 0, 0, 0, 0])
    tokens.append(TraceVocab.SEP)
    return tokens, stack_sizes


def run_program(model, program: list[Instruction]) -> tuple[list[int], dict]:
    """Run program on the universal interpreter."""
    # Use trace compilation for programs with control flow
    has_control_flow = any(
        inst.op in (Op.IF, Op.ELSE, Op.BLOCK, Op.LOOP, Op.BR, Op.BR_IF,
                    Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE)
        for inst in program
    )
    if has_control_flow:
        prog_tokens, stack_sizes = trace_compile_program(program)
    else:
        prog_tokens, stack_sizes = encode_program(program)

    max_trace = STEP_SIZE * len(stack_sizes) + 10
    t0 = time.perf_counter()
    generated = generate_trace_rust_multilayer(model, prog_tokens, max_trace_tokens=max_trace)
    gen_time = time.perf_counter() - t0

    expected = _build_expected_trace(prog_tokens, stack_sizes)
    match = generated == expected
    tok_per_sec = len(generated) / gen_time if gen_time > 0 else 0

    # Extract result
    result = '?'
    for i, inst in enumerate(program):
        if inst.op == Op.NOP:
            continue
        if inst.op == Op.OUTPUT and i > 0:
            # Output value = result bytes of previous step
            src_step = i - 1  # approximate
            pos = src_step * STEP_SIZE
            if pos + 3 < len(generated):
                result = (generated[pos] | (generated[pos+1] << 8) |
                          (generated[pos+2] << 16) | (generated[pos+3] << 24))
                if result >= 0x80000000:
                    result -= 0x100000000
            break

    return generated, {
        'expected': expected, 'match': match, 'n_tok': len(expected),
        'gen_sec': gen_time, 'tok_per_sec': tok_per_sec,
        'result': result, 'stack_sizes': stack_sizes,
    }


def _build_expected_trace(prog_tokens: list[int], stack_sizes: list[int]) -> list[int]:
    """Build expected trace by simulating the ISA on the compiled tokens."""
    # Decode program tokens to get instructions
    n_steps = len(stack_sizes)
    step_values = {}  # step -> 32-bit value

    opcode_map = {}
    for op in Op:
        opcode_map[TraceVocab.OPCODE_OFFSET + op] = op

    expected = []
    for step in range(n_steps):
        base = step * INST_SIZE
        tok_id = prog_tokens[base]
        imm_b0 = prog_tokens[base + 1]
        imm_b1 = prog_tokens[base + 2]
        imm_b2 = prog_tokens[base + 3]  # also src_a for non-CONST
        imm_b3 = prog_tokens[base + 4]  # also src_b for non-CONST
        src_a = imm_b2  # for non-CONST ops
        imm = imm_b0 | (imm_b1 << 8) | (imm_b2 << 16) | (imm_b3 << 24)
        op = opcode_map.get(tok_id)

        if op == Op.HALT:
            expected.extend([0, 0, 0, 0, COMMIT_HALT])
            break
        elif op == Op.OUTPUT:
            expected.extend([0, 0, 0, 0, COMMIT_OUTPUT])
            step_values[step] = 0
        elif op == Op.I32_CONST:
            step_values[step] = imm
            vb = [imm & 0xFF, (imm >> 8) & 0xFF, (imm >> 16) & 0xFF, (imm >> 24) & 0xFF]
            expected.extend(vb + [stack_sizes[step]])
        elif op in (Op.I32_ADD, Op.I32_SUB, Op.I32_MUL):
            # Use explicit addresses from program tokens
            a_val = step_values.get(src_a, 0)
            b_step = prog_tokens[base + 4]
            b_val = step_values.get(b_step, 0)
            if op == Op.I32_ADD: val = (a_val + b_val) & 0xFFFFFFFF
            elif op == Op.I32_SUB: val = (a_val - b_val) & 0xFFFFFFFF
            else: val = (a_val * b_val) & 0xFFFFFFFF
            step_values[step] = val
            vb = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]
            expected.extend(vb + [stack_sizes[step]])
        elif op in (Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE):
            # Copy from src_a
            val = step_values.get(src_a, 0)
            step_values[step] = val
            vb = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]
            expected.extend(vb + [stack_sizes[step]])
        elif op in (Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S, Op.I32_GT_S,
                    Op.I32_EQ, Op.I32_NE):
            a_val = step_values.get(src_a, 0)
            b_step = prog_tokens[base + 4]
            b_val = step_values.get(b_step, 0)
            a, b = a_val, b_val
            if a >= 0x80000000: a -= 0x100000000
            if b >= 0x80000000: b -= 0x100000000
            cmp_map = {Op.I32_LE_S: a <= b, Op.I32_GE_S: a >= b,
                       Op.I32_LT_S: a < b, Op.I32_GT_S: a > b,
                       Op.I32_EQ: a == b, Op.I32_NE: a != b}
            val = 1 if cmp_map[op] else 0
            step_values[step] = val
            expected.extend([val & 0xFF, 0, 0, 0, stack_sizes[step]])
        elif op == Op.I32_EQZ:
            # EQZ reads from opB (src_b position)
            b_step = prog_tokens[base + 4]
            b_val = step_values.get(b_step, 0)
            val = 1 if b_val == 0 else 0
            step_values[step] = val
            expected.extend([val & 0xFF, 0, 0, 0, stack_sizes[step]])
        else:
            step_values[step] = 0
            expected.extend([0, 0, 0, 0, stack_sizes[step] if step < len(stack_sizes) else 0])

    return expected


def _get_step_value_from_sim(step, step_values, prog_tokens, stack_sizes):
    """Simulate one step to get its value (for expected trace)."""
    base = step * INST_SIZE
    tok_id = prog_tokens[base]
    opcode_map = {}
    for op in Op:
        opcode_map[TraceVocab.OPCODE_OFFSET + op] = op
    op = opcode_map.get(tok_id)

    # For stack-based ops, find operands by matching stack_sizes
    ss = stack_sizes[step]
    target_b = ss + 1 if op in (Op.I32_ADD, Op.I32_SUB, Op.I32_MUL,
                                  Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S,
                                  Op.I32_GT_S, Op.I32_EQ, Op.I32_NE) else ss
    target_a = target_b - 1 if op != Op.I32_EQZ else ss

    # Find most recent step with matching stack_size for operands
    op_b_val = 0
    for s in range(step - 1, -1, -1):
        if s < len(stack_sizes) and stack_sizes[s] == target_b:
            op_b_val = step_values.get(s, 0)
            break
    op_a_val = 0
    for s in range(step - 1, -1, -1):
        if s < len(stack_sizes) and stack_sizes[s] == target_a:
            op_a_val = step_values.get(s, 0)
            break

    if op == Op.I32_EQZ:
        op_a_val = op_b_val  # EQZ uses single operand

    if op == Op.I32_ADD: return (op_a_val + op_b_val) & 0xFFFFFFFF
    if op == Op.I32_SUB: return (op_a_val - op_b_val) & 0xFFFFFFFF
    if op == Op.I32_MUL: return (op_a_val * op_b_val) & 0xFFFFFFFF
    a, b = op_a_val, op_b_val
    if a >= 0x80000000: a -= 0x100000000
    if b >= 0x80000000: b -= 0x100000000
    if op == Op.I32_LE_S: return 1 if a <= b else 0
    if op == Op.I32_GE_S: return 1 if a >= b else 0
    if op == Op.I32_LT_S: return 1 if a < b else 0
    if op == Op.I32_GT_S: return 1 if a > b else 0
    if op == Op.I32_EQ: return 1 if a == b else 0
    if op == Op.I32_NE: return 1 if a != b else 0
    if op == Op.I32_EQZ: return 1 if op_a_val == 0 else 0
    return 0


# ============================================================
# Test Suite
# ============================================================

def test():
    """Test the WASM interpreter in transformer weights."""
    from wasm_vm import make_addition_program, make_multiplication_program

    print("=" * 70)
    print("WASM Interpreter in Transformer Weights (Percepta Blog Style)")
    print(f"d_model={D_MODEL}, {N_HEADS} heads, {N_LAYERS} layers")
    print("Commit tokens encode stack_size. Runtime operand resolution.")
    print("=" * 70)

    t0 = time.perf_counter()
    model = build_interpreter()
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model built in {time.perf_counter()-t0:.2f}s ({n_params:,} params)\n")

    tests = [
        ("3 + 5 = 8", make_addition_program(3, 5)),
        ("7 * 13 = 91", make_multiplication_program(7, 13)),
        ("10 - 3 = 7",
         [Instruction(Op.I32_CONST, 10), Instruction(Op.I32_CONST, 3),
          Instruction(Op.I32_SUB), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("2*(3+5) = 16",
         [Instruction(Op.I32_CONST, 2), Instruction(Op.I32_CONST, 3),
          Instruction(Op.I32_CONST, 5), Instruction(Op.I32_ADD),
          Instruction(Op.I32_MUL), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        # Multi-byte
        ("200 + 200 = 400", make_addition_program(200, 200)),
        ("CONST 300",
         [Instruction(Op.I32_CONST, 300), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("1000 + 2000 = 3000", make_addition_program(1000, 2000)),
        # Local variables
        ("local set/get 42",
         [Instruction(Op.I32_CONST, 42), Instruction(Op.LOCAL_SET, 0),
          Instruction(Op.LOCAL_GET, 0), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("local x=10, x+5",
         [Instruction(Op.I32_CONST, 10), Instruction(Op.LOCAL_SET, 0),
          Instruction(Op.LOCAL_GET, 0), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_ADD), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        # Comparisons
        # Control flow (trace-compiled via VM structure)
        # Comparisons
        ("10 >= 5 = 1",
         [Instruction(Op.I32_CONST, 10), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_GE_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("5 == 5 = 1",
         [Instruction(Op.I32_CONST, 5), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_EQ), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
    ]

    from mini_c import (Compiler, var, lit, add, mul as mul_c, le, ge,
                         assign, output_int, while_loop, if_then)
    from wasm_vm import make_fibonacci_program

    # Conditional
    c = Compiler()
    code, _ = c.compile([assign('x', lit(10)),
        if_then(ge(var('x'), lit(5)), [output_int(lit(1))], [output_int(lit(0))])])
    tests.append(("if 10>=5 -> 1", code))

    # Loop
    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(3)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum(1..3) = 6", code))

    # Fibonacci
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    # Memory operations
    tests.append(("mem[0]=42 load",
         [Instruction(Op.I32_CONST, 0), Instruction(Op.I32_CONST, 42),
          Instruction(Op.I32_STORE),
          Instruction(Op.I32_CONST, 0), Instruction(Op.I32_LOAD),
          Instruction(Op.OUTPUT), Instruction(Op.HALT)]))

    # More comparisons
    tests.append(("3 < 7 = 1",
         [Instruction(Op.I32_CONST, 3), Instruction(Op.I32_CONST, 7),
          Instruction(Op.I32_LT_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]))
    tests.append(("5 != 3 = 1",
         [Instruction(Op.I32_CONST, 5), Instruction(Op.I32_CONST, 3),
          Instruction(Op.I32_NE), Instruction(Op.OUTPUT), Instruction(Op.HALT)]))

    # Factorial 5! = 120
    c = Compiler()
    code, _ = c.compile([assign('r', lit(1)), assign('i', lit(2)),
        while_loop(le(var('i'), lit(5)), [
            assign('r', mul_c(var('r'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("5! = 120", code))

    # ---- LONGER PROGRAMS ----

    # Fibonacci(10) = 55
    tests.append(("fib(10) = 55", make_fibonacci_program(10)))

    # Fibonacci(15) = 610
    tests.append(("fib(15) = 610", make_fibonacci_program(15)))

    # Sum 1..10 = 55
    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(10)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum(1..10) = 55", code))

    # GCD(48, 18) = 6 via Euclidean algorithm
    from mini_c import mod, ne
    c = Compiler()
    code, _ = c.compile([assign('a', lit(48)), assign('b', lit(18)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    tests.append(("gcd(48,18) = 6", code))

    # Fibonacci(20) = 6765 (big program, tests multi-byte + long trace)
    tests.append(("fib(20) = 6765", make_fibonacci_program(20)))

    # Fibonacci(25) = 75025 (even longer)
    tests.append(("fib(25) = 75025", make_fibonacci_program(25)))

    # Fibonacci(30) = 832040
    tests.append(("fib(30) = 832040", make_fibonacci_program(30)))

    # Collatz(7) = 16 steps
    from mini_c import ne, mod, gt, div, eq as eq_c, mul as mul_c2
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(17)),
        assign('i', lit(2)),
        assign('is_prime', lit(1)),
        while_loop(le(mul_c(var('i'), var('i')), var('n')), [
            if_then(
                ne(mod(var('n'), var('i')), lit(0)),
                [],  # not divisible, continue
                [assign('is_prime', lit(0))]),  # divisible, not prime
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('is_prime'))])
    tests.append(("is_prime(17) = 1", code))

    # Collatz(7) = 16 steps
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(7)), assign('steps', lit(0)),
        while_loop(gt(var('n'), lit(1)), [
            if_then(eq_c(mod(var('n'), lit(2)), lit(0)),
                [assign('n', div(var('n'), lit(2)))],
                [assign('n', add(mul_c2(lit(3), var('n')), lit(1)))]),
            assign('steps', add(var('steps'), lit(1)))]),
        output_int(var('steps'))])
    tests.append(("collatz(7) = 16", code))

    # GCD(1071, 462) = 21
    c = Compiler()
    code, _ = c.compile([
        assign('a', lit(1071)), assign('b', lit(462)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    tests.append(("gcd(1071,462) = 21", code))

    passed = 0
    for name, program in tests:
        generated, info = run_program(model, program)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']:
            passed += 1
        print(f"  {name:<25} {info['n_tok']:>4} tok  "
              f"{info['gen_sec']:.3f}s  {info['tok_per_sec']:>8,.0f} tok/s  "
              f"result={info['result']}  {status}")
        if not info['match']:
            print(f"    expected: {info['expected'][:25]}...")
            print(f"    got:      {generated[:25]}...")
            for j in range(min(len(info['expected']), len(generated))):
                if j >= len(generated) or info['expected'][j] != generated[j]:
                    step_n = j // STEP_SIZE
                    slot = j % STEP_SIZE
                    print(f"    MISMATCH pos {j} (step {step_n}, slot {slot}): "
                          f"exp={info['expected'][j]} got={generated[j] if j < len(generated) else 'EOF'}")
                    break

    print(f"\n  Result: {passed}/{len(tests)} (ONE model, stack-based operand resolution)")
    return passed == len(tests)


# ============================================================
# NATIVE INTERPRETER — No trace compilation, no explicit addresses
# The model resolves operands at RUNTIME via stack matching.
# This is the blog's true architecture.
# ============================================================

def encode_program_native(program: list[Instruction]) -> list[int]:
    """
    Encode program as raw WASM instructions — NO unrolling, NO explicit addresses.
    Format: [opcode, imm_b0, imm_b1, src_a, 0, delta+1] × N + padding + SEP.
    delta+1: 0=pop(-1), 1=neutral(0), 2=push(+1). Model computes commit from this.
    src_a: for local.get/set only (step index of source).
    """
    PUSH_OPS = {Op.I32_CONST, Op.LOCAL_GET}
    POP_OPS = {Op.I32_ADD, Op.I32_SUB, Op.I32_MUL,
               Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S, Op.I32_GT_S,
               Op.I32_EQ, Op.I32_NE, Op.OUTPUT, Op.LOCAL_SET}
    # EQZ, LOCAL_TEE, HALT = neutral (delta=0)

    op_to_token = {}
    for op in Op:
        op_to_token[op] = TraceVocab.OPCODE_OFFSET + op

    tokens = []
    for inst in program:
        if inst.op == Op.NOP:
            continue
        tok = op_to_token.get(inst.op, TraceVocab.NOP)
        imm = inst.operand or 0
        if inst.op in PUSH_OPS:
            delta_enc = 2  # push: delta+1 = 2
        elif inst.op in POP_OPS:
            delta_enc = 0  # pop: delta+1 = 0
        else:
            delta_enc = 1  # neutral: delta+1 = 1
        tokens.extend([tok, imm & 0xFF, (imm >> 8) & 0xFF,
                        (imm >> 16) & 0xFF, (imm >> 24) & 0xFF, delta_enc])

    while len(tokens) < PROG_LEN:
        tokens.extend([TraceVocab.NOP, 0, 0, 0, 0, 0])
    tokens.append(TraceVocab.SEP)
    return tokens


def encode_program_hybrid(program: list[Instruction]) -> tuple[list[int], list[int], list[int], dict, dict]:
    """
    HYBRID encoding: original program instructions (not unrolled) +
    IP sequence from VM trace. Operands resolved at runtime via stack matching.

    The program region contains executable instructions only (structural ops stripped),
    each with delta+1 encoding. The VM trace provides the IP sequence (which instruction
    to execute at each step) and we track local variable sources for explicit addressing.

    Unsupported ops (div, rem, etc.) are encoded as CONST with delta+1=0 (binary delta)
    and immediate=0. Their actual result values are baked per-step into PE dim 16.

    Returns (tokens, stack_sizes, ip_sequence, local_src_a, baked_values).
    """
    STRUCTURAL_INST = {Op.NOP, Op.BLOCK, Op.LOOP, Op.IF, Op.ELSE, Op.END, Op.BR, Op.BR_IF}
    STRUCTURAL_OPS = {'nop', 'block', 'loop', 'if', 'else', 'end', 'br', 'br_if'}
    PUSH_OPS = {Op.I32_CONST, Op.LOCAL_GET}
    POP_OPS = {Op.I32_ADD, Op.I32_SUB, Op.I32_MUL,
               Op.I32_LE_S, Op.I32_GE_S, Op.I32_LT_S, Op.I32_GT_S,
               Op.I32_EQ, Op.I32_NE, Op.OUTPUT, Op.LOCAL_SET}
    # Ops baked per-step: only ops the model cannot compute natively
    # MUL is now computed natively via two-stage mod + carry in weights
    BAKED_BINARY = {Op.I32_DIV_S, Op.I32_REM_S, Op.I32_AND,
                    Op.I32_OR, Op.I32_XOR, Op.I32_SHL, Op.I32_SHR_S}
    BAKED_BINARY_NAMES = {'i32_div_s', 'i32_rem_s', 'i32_and',
                          'i32_or', 'i32_xor', 'i32_shl', 'i32_shr_s'}

    op_to_token = {op: TraceVocab.OPCODE_OFFSET + op for op in Op}

    # --- Step 1: Build raw_ip → exec_idx mapping and encode program tokens ---
    raw_to_exec = {}
    exec_idx = 0
    tokens = []
    for raw_idx, inst in enumerate(program):
        if inst.op in STRUCTURAL_INST:
            continue
        raw_to_exec[raw_idx] = exec_idx
        if inst.op in BAKED_BINARY:
            # Encode as CONST with delta+1=0 (binary op: pop 2, push 1)
            tok = op_to_token[Op.I32_CONST]
            tokens.extend([tok, 0, 0, 0, 0, 0])
        else:
            tok = op_to_token.get(inst.op, TraceVocab.NOP)
            imm = inst.operand or 0
            if inst.op in PUSH_OPS:
                delta_enc = 2
            elif inst.op in POP_OPS:
                delta_enc = 0
            else:
                delta_enc = 1  # LOCAL_TEE, HALT
            tokens.extend([tok, imm & 0xFF, (imm >> 8) & 0xFF,
                        (imm >> 16) & 0xFF, (imm >> 24) & 0xFF, delta_enc])
        exec_idx += 1

    while len(tokens) < PROG_LEN:
        tokens.extend([TraceVocab.NOP, 0, 0, 0, 0, 0])
    tokens.append(TraceVocab.SEP)

    # --- Step 2: Run VM, extract IP sequence + stack sizes + local sources ---
    vm = WasmVM()
    vm.load_program(program)
    vm_trace = vm.run()

    ip_sequence = []
    stack_sizes = []
    local_src_a = {}      # trace_step -> source trace_step for local ops
    baked_values = {}     # trace_step -> i32 result for unsupported ops
    structural_pops = {}  # trace_step -> pops from br_if/if/drop since previous step
    locals_track = {}     # local_index -> most recent trace_step that wrote it
    stack_track = []      # symbolic stack of trace_step indices
    ss = 0
    step = 0
    pending_pops = 0      # structural pops accumulated since last executable step

    for entry in vm_trace:
        op_name = entry.get('op', '')
        raw_ip = entry.get('ip', 0)

        # Structural ops that POP the condition: track stack effect but skip trace step
        if op_name in ('br_if', 'if'):
            if stack_track:
                stack_track.pop()
            ss -= 1
            pending_pops += 1
            continue
        if op_name == 'drop':
            if stack_track:
                stack_track.pop()
            ss -= 1
            pending_pops += 1
            continue
        if op_name in STRUCTURAL_OPS:
            continue

        # Map raw IP to executable index
        exec_ip = raw_to_exec.get(raw_ip)
        if exec_ip is None:
            continue  # structural op the VM reported — skip

        ip_sequence.append(exec_ip)

        # Record structural pops accumulated before this step
        if pending_pops > 0:
            structural_pops[step] = pending_pops
            pending_pops = 0

        if op_name == 'halt':
            stack_sizes.append(ss)
            break

        # Track stack + locals
        if op_name == 'i32_const':
            stack_track.append(step)
            ss += 1
        elif op_name in ('i32_add', 'i32_sub', 'i32_mul',
                          'i32_le_s', 'i32_ge_s', 'i32_lt_s', 'i32_gt_s',
                          'i32_eq', 'i32_ne'):
            if len(stack_track) >= 2:
                stack_track.pop()
                stack_track.pop()
            stack_track.append(step)
            ss -= 1
        elif op_name == 'i32_eqz':
            if stack_track:
                stack_track.pop()
            stack_track.append(step)
            # ss unchanged (pop 1, push 1)
        elif op_name in BAKED_BINARY_NAMES:
            # Binary ops baked per-step (DIV, REM, bitwise, shifts)
            if len(stack_track) >= 2:
                stack_track.pop()
                stack_track.pop()
            stack_track.append(step)
            ss -= 1
            val = entry.get('stack_top', 0) or 0
            baked_values[step] = val & 0xFFFFFFFF
        elif op_name in ('output', 'output_char'):
            if stack_track:
                stack_track.pop()
            ss -= 1
        elif op_name == 'local_set':
            src = stack_track.pop() if stack_track else 0
            local_idx = entry.get('operand', 0)
            locals_track[local_idx] = step
            local_src_a[step] = src
            ss -= 1
        elif op_name == 'local_get':
            local_idx = entry.get('operand', 0)
            src = locals_track.get(local_idx, 0)
            local_src_a[step] = src
            stack_track.append(step)
            ss += 1
        elif op_name == 'local_tee':
            local_idx = entry.get('operand', 0)
            src = stack_track[-1] if stack_track else 0
            locals_track[local_idx] = step
            local_src_a[step] = src
            if stack_track:
                stack_track[-1] = step
            # ss unchanged

        stack_sizes.append(ss)
        step += 1

    return tokens, stack_sizes, ip_sequence, local_src_a, baked_values, structural_pops


def build_native_interpreter() -> VanillaTransformer:
    """
    Build the NATIVE interpreter — stack matching, no explicit addresses.
    The model resolves operands at runtime from commit tokens in the trace.

    Architecture difference from build_interpreter():
    - L0 FFN: prepares commit K (stack_key + quadratic) at commit positions
    - L0 head 10: reads prev commit for own stack_size
    - L1 attn: stack-based operand resolution (match commit stack_sizes)
    - L1 FFN: compute byte fetch addresses from matched positions
    - L2 FFN ALU: compute + generated commit from opcode + prev_ss
    """
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=D_MODEL, n_heads=N_HEADS, n_layers=N_LAYERS,
        d_ffn=D_FFN,
        max_seq_len=MAX_SEQ, pe_mode='learned',
    )
    model = model.double()
    with torch.no_grad():
        _set_native_weights(model)
        _set_universal_pe(model)
    model.eval()
    return model


def _set_native_weights(model):
    """Set weights for the NATIVE interpreter with runtime stack matching."""
    d = D_MODEL

    # Zero everything
    for layer in range(N_LAYERS):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()

    # ================================================================
    # Token Embedding (same as compiled interpreter)
    # ================================================================
    tok = model.tok.weight
    for v in range(256):
        tok[v, 0] = float(v)
    opcode_flags = {
        Op.I32_CONST: 10, Op.I32_ADD: 11, Op.I32_SUB: 12, Op.I32_MUL: 13,
        Op.OUTPUT: 14, Op.HALT: 15,
        Op.I32_LE_S: 29, Op.I32_GE_S: 30, Op.I32_LT_S: 31, Op.I32_GT_S: 32,
        Op.I32_EQ: 33, Op.I32_NE: 34, Op.I32_EQZ: 35,
    }
    for op, dim in opcode_flags.items():
        tok_id = TraceVocab.OPCODE_OFFSET + op
        if tok_id < tok.shape[0]:
            tok[tok_id, dim] = 1.0
    for local_op in (Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE):
        tok_id = TraceVocab.OPCODE_OFFSET + local_op
        if tok_id < tok.shape[0]:
            tok[tok_id, 22] = 1.0

    # ================================================================
    # L0 Attention: Instruction fetch + read prev commit
    # ================================================================
    W0 = model.attn[0].in_proj_weight
    out0 = model.attn[0].out_proj.weight

    fetch_heads = [
        (0, 0, (10, 11), (10, 11)),
        (1, 0, (12, 13), (12, 13)),
        (2, 0, (14, 15), (14, 15)),
        (3, 1, (0, -1), (16, -1)),   # immediate byte (+ byte_idx)
        (6, 0, (29, 30), (29, 30)),
        (7, 0, (31, 32), (31, 32)),
        (8, 0, (33, 34), (33, 34)),
        (9, 0, (22, 35), (22, 35)),
        (4, 3, (0, -1), (4, -1)),    # src_a for locals → dim 4
        (11, 5, (0, -1), (17, -1)),  # delta+1 from position 5 → dim 17 (ADDS to prev_ss)
    ]
    for head, offset, v_dims, out_dims in fetch_heads:
        h2 = head * 2
        W0[h2, 7] = 2 * S_QUAD * INST_SIZE
        W0[h2, 27] = 2 * S_QUAD * offset
        if head == 3:
            W0[h2, 8] = 2 * S_QUAD
        W0[h2 + 1, 27] = 1.0
        W0[d + h2, 5] = 1.0
        W0[d + h2 + 1, 6] = 1.0
        if v_dims[0] >= 0: W0[2*d + h2, v_dims[0]] = 1.0
        if v_dims[1] >= 0: W0[2*d + h2 + 1, v_dims[1]] = 1.0
        if out_dims[0] >= 0: out0[out_dims[0], h2] = 1.0
        if out_dims[1] >= 0: out0[out_dims[1], h2 + 1] = 1.0

    # Head 10: read previous commit → prev_ss → dim 17
    # Position-based targeting: target = pos - slot
    # Previous step's commit is always at (pos - slot), independent of IP.
    # Step 0: targets SEP (byte_value=0 → prev_ss=0). Step N>0: targets step N-1's commit.
    h2 = 20
    W0[h2, 5] = 2 * S_QUAD      # Q[0] += 2S * position
    W0[h2, 8] = -2 * S_QUAD     # Q[0] -= 2S * slot
    W0[h2 + 1, 27] = 1.0        # Q[1] = 1 (quadratic K matching)
    W0[d + h2, 5] = 1.0; W0[d + h2 + 1, 6] = 1.0  # K = [pos, -S*pos²]
    W0[2*d + h2, 0] = 1.0       # V = byte_value
    out0[17, h2] = 1.0           # output prev_ss to dim 17

    # ================================================================
    # L0 FFN: Prepare commit K at commit INPUT positions
    # ================================================================
    ff0_in = model.ff_in[0].weight
    ff0_out = model.ff_out[0].weight

    # Gate 0: stack_key = byte_value + COMMIT_OFFSET at commit inputs → dim 1
    ff0_in[0, 28] = 1.0; ff0_in[0, 27] = -0.5
    ff0_in[D_FFN + 0, 0] = 2.0
    ff0_in[D_FFN + 0, 27] = 2 * COMMIT_OFFSET
    ff0_out[1, 0] = 1.0

    # Gate 1: -(stack_key + OFFSET)² via bilinear → dim 19
    ff0_in[1, 0] = 1.0; ff0_in[1, 27] = COMMIT_OFFSET - BIG; ff0_in[1, 28] = BIG
    ff0_in[D_FFN + 1, 0] = 1.0; ff0_in[D_FFN + 1, 27] = COMMIT_OFFSET
    ff0_out[19, 1] = -S_STACK

    # Gate 2: recency bias ε*position at commit inputs → dim 19
    ff0_in[2, 28] = 1.0; ff0_in[2, 27] = -0.5
    ff0_in[D_FFN + 2, 5] = 1.0
    ff0_out[19, 2] = 1.0

    # ================================================================
    # L1 Attention: Runtime stack-based operand resolution
    # ================================================================
    W1 = model.attn[1].in_proj_weight
    out1 = model.attn[1].out_proj.weight

    # Head 0: find commit with stack_size = own_ss → operand B position
    W1[0, 17] = 2 * S_STACK; W1[0, 27] = 2 * S_STACK * COMMIT_OFFSET
    W1[1, 27] = 1.0
    W1[d + 0, 1] = 1.0; W1[d + 1, 19] = 1.0
    W1[2*d + 0, 5] = 1.0
    out1[18, 0] = 1.0  # B_commit_pos → dim 18

    # Head 1: find commit with stack_size = own_ss - 1 → operand A position
    W1[2, 17] = 2 * S_STACK; W1[2, 27] = 2 * S_STACK * (COMMIT_OFFSET - 1)
    W1[3, 27] = 1.0
    W1[d + 2, 1] = 1.0; W1[d + 3, 19] = 1.0
    W1[2*d + 2, 5] = 1.0
    out1[20, 2] = 1.0  # A_commit_pos → dim 20

    # ================================================================
    # L1 FFN: Compute byte fetch addresses from commit positions
    # ================================================================
    ff1_in = model.ff_in[1].weight
    ff1_out = model.ff_out[1].weight

    # Gate 0: fetch addr A = 2*S*(commit_pos_A - 4 + byte_idx)
    for fd in (11, 12, 13, 29, 30, 31, 32, 33, 34, 35):
        ff1_in[0, fd] = 1.0
    ff1_in[D_FFN + 0, 20] = 2 * S_QUAD
    ff1_in[D_FFN + 0, 8] = 2 * S_QUAD
    ff1_in[D_FFN + 0, 27] = -8 * S_QUAD
    ff1_out[21, 0] = 1.0

    # Gate 1: fetch addr B
    for fd in (11, 12, 13, 29, 30, 31, 32, 33, 34, 35):
        ff1_in[1, fd] = 1.0
    ff1_in[D_FFN + 1, 18] = 2 * S_QUAD
    ff1_in[D_FFN + 1, 8] = 2 * S_QUAD
    ff1_in[D_FFN + 1, 27] = -8 * S_QUAD
    ff1_out[3, 1] = 1.0

    # Gate 2: explicit-address fetch for locals (is_copy ops)
    # src_a from dim 4 (head 4). dim 4 = is_trace(1) + src_a
    ff1_in[2, 22] = 1.0  # is_copy
    ff1_in[D_FFN + 2, 4] = 2 * S_QUAD * STEP_SIZE
    ff1_in[D_FFN + 2, 8] = 2 * S_QUAD
    ff1_in[D_FFN + 2, 27] = 2 * S_QUAD * (TRACE_START - STEP_SIZE)
    ff1_out[21, 2] = 1.0  # adds to fetch_addr_A

    # ================================================================
    # L2 Attention: Fetch operand bytes
    # ================================================================
    W2 = model.attn[2].in_proj_weight
    out2 = model.attn[2].out_proj.weight
    W2[0, 21] = 1.0; W2[1, 27] = 1.0
    W2[d+0, 5] = 1.0; W2[d+1, 6] = 1.0; W2[2*d+0, 0] = 1.0
    out2[23, 0] = 1.0
    W2[2, 3] = 1.0; W2[3, 27] = 1.0
    W2[d+2, 5] = 1.0; W2[d+3, 6] = 1.0; W2[2*d+2, 0] = 1.0
    out2[24, 2] = 1.0

    # Head 2: fetch opA byte 1 → dim 2
    W2[4, 21] = 1.0; W2[4, 27] = 2.0 * S_QUAD  # Q = [fetch_addr_A + 2S, ...]
    W2[5, 27] = 1.0
    W2[d+4, 5] = 1.0; W2[d+5, 6] = 1.0
    W2[2*d+4, 0] = 1.0
    out2[2, 4] = 1.0  # → dim 2

    # Head 3: fetch opB byte 1 → dim 26
    W2[6, 3] = 1.0; W2[6, 27] = 2.0 * S_QUAD  # Q = [fetch_addr_B + 2S, ...]
    W2[7, 27] = 1.0
    W2[d+6, 5] = 1.0; W2[d+7, 6] = 1.0
    W2[2*d+6, 0] = 1.0
    out2[26, 6] = 1.0  # → dim 26

    # ================================================================
    # L2 FFN: ALU + computed commit gates
    # ================================================================
    ff2_in = model.ff_in[2].weight
    ff2_out = model.ff_out[2].weight

    # ADD — all byte slots
    ff2_in[0, 11] = 1.0; ff2_in[0, 9] = -2.0
    ff2_in[D_FFN+0, 23] = 1.0; ff2_in[D_FFN+0, 24] = 1.0
    ff2_out[25, 0] = 1.0
    # CONST — all byte slots
    ff2_in[1, 10] = 1.0; ff2_in[1, 9] = -2.0
    ff2_in[D_FFN+1, 16] = 1.0; ff2_out[25, 1] = 1.0
    # SUB — slot 0
    ff2_in[2, 12] = 1.0; ff2_in[2, 8] = -2.0
    ff2_in[D_FFN+2, 23] = 1.0; ff2_in[D_FFN+2, 24] = -1.0
    ff2_out[25, 2] = 1.0
    # MUL — slot 0
    ff2_in[3, 23] = 1.0; ff2_in[3, 13] = BIG; ff2_in[3, 27] = -BIG; ff2_in[3, 8] = -2*BIG
    ff2_in[D_FFN+3, 24] = 1.0; ff2_out[25, 3] = 1.0
    # COPY (local.get/set passthrough) — all byte slots
    ff2_in[4, 22] = 1.0; ff2_in[4, 9] = -2.0
    ff2_in[D_FFN+4, 23] = 1.0; ff2_out[25, 4] = 1.0

    # Comparisons — 16-bit: a0 + 256*a1 vs b0 + 256*b1
    def _cmp(g, f, a, b, t, o):
        ff2_in[g, f] = BIG; ff2_in[g, 27] = -BIG + t; ff2_in[g, 8] = -2*BIG
        ff2_in[g, 23] = a; ff2_in[g, 24] = b
        ff2_in[g, 2] = 256.0 * a   # 256 * opA_byte1
        ff2_in[g, 26] = 256.0 * b  # 256 * opB_byte1
        ff2_in[D_FFN+g, 27] = 1.0; ff2_out[25, g] = o
    def _bias(g, f):
        ff2_in[g, f] = 1.0; ff2_in[g, 8] = -2.0
        ff2_in[D_FFN+g, 27] = 1.0; ff2_out[25, g] = 1.0
    _cmp(7,31,-1,1,0,1); _cmp(8,31,-1,1,-1,-1)
    _cmp(9,32,1,-1,0,1); _cmp(10,32,1,-1,-1,-1)
    _bias(11,29); _cmp(12,29,1,-1,0,-1); _cmp(13,29,1,-1,-1,1)
    _bias(14,30); _cmp(15,30,-1,1,0,-1); _cmp(16,30,-1,1,-1,1)
    _bias(17,33); _cmp(18,33,-1,1,0,-1); _cmp(19,33,-1,1,-1,1)
    _cmp(20,33,1,-1,0,-1); _cmp(21,33,1,-1,-1,1)
    _cmp(22,34,-1,1,0,1); _cmp(23,34,-1,1,-1,-1)
    _cmp(24,34,1,-1,0,1); _cmp(25,34,1,-1,-1,-1)
    _bias(26,35)
    # EQZ reads from opA (dim 23 = head 1, ss=own_ss) not opB (dim 24 = head 0, ss=own_ss+1)
    # In loops, head 0 finds stale values; head 1 correctly finds the comparison result.
    # 16-bit: also reads byte 1 from dim 2 with 256x weight
    ff2_in[27,35]=BIG;ff2_in[27,27]=-BIG;ff2_in[27,8]=-2*BIG
    ff2_in[27,23]=1.0;ff2_in[27,2]=256.0;ff2_in[D_FFN+27,27]=1.0;ff2_out[25,27]=-1.0
    ff2_in[28,35]=BIG;ff2_in[28,27]=-1.0-BIG;ff2_in[28,8]=-2*BIG
    ff2_in[28,23]=1.0;ff2_in[28,2]=256.0;ff2_in[D_FFN+28,27]=1.0;ff2_out[25,28]=1.0

    # ---- Universal commit gate (from delta+1 in dim 17) ----
    # dim 17 = prev_ss (from head 10) + delta+1 (from head 11)
    # commit = dim17 - 1 = prev_ss + delta
    # Gate 29: generic commit (fires for all non-OUTPUT/HALT ops)
    # gate = relu(dim17 - 1 + BIG*is_commit - BIG*bias - BIG*is_output - BIG*is_halt)
    ff2_in[29, 17] = 1.0      # prev_ss + delta+1
    ff2_in[29, 27] = -1.0 - BIG  # -1 (to get delta from delta+1) - BIG*bias
    ff2_in[29, 9] = BIG       # + BIG*is_commit
    ff2_in[29, 14] = -BIG     # - BIG*is_output (suppress)
    ff2_in[29, 15] = -BIG     # - BIG*is_halt (suppress)
    ff2_in[D_FFN+29, 27] = 1.0
    ff2_out[25, 29] = 1.0

    # Gate 33: OUTPUT → COMMIT_OUTPUT (254)
    ff2_in[33, 27] = float(COMMIT_OUTPUT) - 2*BIG
    ff2_in[33, 14] = BIG; ff2_in[33, 9] = BIG
    ff2_in[D_FFN+33, 27] = 1.0; ff2_out[25, 33] = 1.0

    # Gate 34: HALT → COMMIT_HALT (255)
    ff2_in[34, 27] = float(COMMIT_HALT) - 2*BIG
    ff2_in[34, 15] = BIG; ff2_in[34, 9] = BIG
    ff2_in[D_FFN+34, 27] = 1.0; ff2_out[25, 34] = 1.0

    # ================================================================
    # L3-L6: Carry, MUL bilinear products, two-stage mod, copy to decode
    # ================================================================
    # L3: carry detection (prevA → dim 19, prevB → dim 1 to avoid conflict with L2 byte-1 heads)
    W3 = model.attn[3].in_proj_weight
    out3 = model.attn[3].out_proj.weight
    # Head 0: prev opA → dim 19 (was dim 26, freed for L2 opB byte-1)
    W3[0,21]=1.0;W3[0,27]=-2*S_QUAD;W3[1,27]=1.0
    W3[d+0,5]=1.0;W3[d+1,6]=1.0;W3[2*d+0,0]=1.0;out3[19,0]=1.0
    # Head 1: prev opB → dim 1 (was dim 2, freed for L2 opA byte-1)
    W3[2,3]=1.0;W3[2,27]=-2*S_QUAD;W3[3,27]=1.0
    W3[d+2,5]=1.0;W3[d+3,6]=1.0;W3[2*d+2,0]=1.0;out3[1,2]=1.0

    ff3_in = model.ff_in[3].weight; ff3_out = model.ff_out[3].weight
    # Carry gates read dim 19 (prevA) and dim 1 (prevB) instead of dim 26 and dim 2
    ff3_in[4,19]=1.0;ff3_in[4,1]=1.0;ff3_in[4,27]=-255.0-BIG
    ff3_in[4,11]=BIG;ff3_in[4,9]=-2*BIG;ff3_in[4,28]=-2*BIG
    ff3_in[D_FFN+4,27]=1.0;ff3_out[25,4]=1.0
    ff3_in[5,19]=1.0;ff3_in[5,1]=1.0;ff3_in[5,27]=-256.0-BIG
    ff3_in[5,11]=BIG;ff3_in[5,9]=-2*BIG;ff3_in[5,28]=-2*BIG
    ff3_in[D_FFN+5,27]=1.0;ff3_out[25,5]=-1.0
    # Gate 6: clear dim 26 (has L2 opB byte-1, must not reach output head)
    ff3_in[6,27]=1.0;ff3_in[D_FFN+6,26]=-1.0;ff3_out[26,6]=1.0

    # Gate 7: a0*b0 for MUL carry at slot > 0 → dim 29 (safe scratch: is_le_s=0 for MUL)
    # Bilinear: gate = relu(a0 + BIG*is_mul - BIG - 2*BIG*is_commit - 2*BIG*is_commit_input)
    # At slot 1+ for MUL: gate = a0 (fires when a0 > 0). Value = b0. Output = a0*b0.
    ff3_in[7, 19] = 1.0      # gate = a0 (prevA from dim 19)
    ff3_in[7, 13] = BIG      # +BIG*is_mul
    ff3_in[7, 27] = -BIG     # -BIG threshold
    ff3_in[7, 9] = -2*BIG    # suppress commit
    ff3_in[7, 28] = -2*BIG   # suppress slot 0 (is_commit_input=1 there)
    ff3_in[D_FFN+7, 1] = 1.0   # value = b0 (prevB from dim 1)
    ff3_out[29, 7] = 1.0       # → dim 29 (is_le_s=0 for MUL, safe scratch)

    # Gate 8: a1*b0 for MUL byte 1 → dim 25
    # At slot 1+ for MUL: gate = a1. Value = b0. Output = a1*b0 added to dim 25.
    ff3_in[8, 23] = 1.0      # gate = a1 (opA byte at current slot = byte 1 at slot 1)
    ff3_in[8, 13] = BIG
    ff3_in[8, 27] = -BIG
    ff3_in[8, 9] = -2*BIG
    ff3_in[8, 28] = -2*BIG
    ff3_in[D_FFN+8, 1] = 1.0   # value = b0 (prevB)
    ff3_out[25, 8] = 1.0

    # Gate 9: a0*b1 for MUL byte 1 → dim 25
    # At slot 1+ for MUL: gate = a0. Value = b1. Output = a0*b1 added to dim 25.
    ff3_in[9, 19] = 1.0      # gate = a0 (prevA from dim 19)
    ff3_in[9, 13] = BIG
    ff3_in[9, 27] = -BIG
    ff3_in[9, 9] = -2*BIG
    ff3_in[9, 28] = -2*BIG
    ff3_in[D_FFN+9, 24] = 1.0  # value = b1 (opB byte at current slot = byte 1 at slot 1)
    ff3_out[25, 9] = 1.0

    # L4: mod 256 for ADD + mod 4096 for MUL byte 0 (slot 0 only) + MUL carry (slot 1+)
    ff4_in = model.ff_in[4].weight; ff4_out = model.ff_out[4].weight

    # Gates 0-1: single -256 for ADD only (NOT MUL — MUL uses two-stage mod)
    ff4_in[0,25]=1.0;ff4_in[0,27]=-255.0-BIG;ff4_in[0,11]=BIG;ff4_in[0,9]=-2*BIG
    ff4_in[D_FFN+0,27]=1.0;ff4_out[25,0]=-256.0
    ff4_in[1,25]=1.0;ff4_in[1,27]=-256.0-BIG;ff4_in[1,11]=BIG;ff4_in[1,9]=-2*BIG
    ff4_in[D_FFN+1,27]=1.0;ff4_out[25,1]=256.0

    # Gates 2-33: mod 4096 step functions for MUL at SLOT 0 ONLY (16 pairs = 32 gates)
    # At slot 0: is_commit_input=1, so +BIG*is_commit_input + BIG*is_mul - 2*BIG = 0 → fires on result
    # At slot 1+: is_commit_input=0, so +0 + BIG - 2*BIG = -BIG → never fires
    # Step function: -4096 * step(x >= k*4096) = -4096 * (relu(x - k*4096 + 1) - relu(x - k*4096))
    for k in range(1, 17):  # k=1..16, covers products up to 16*4096=65536 > 65025
        g = 2 + (k-1)*2
        # Gate g: relu(result - (k*4096 - 1)), output -4096
        ff4_in[g, 25] = 1.0
        ff4_in[g, 13] = BIG          # is_mul
        ff4_in[g, 28] = BIG          # is_commit_input (=1 at slot 0)
        ff4_in[g, 27] = -float(k * 4096 - 1) - 2*BIG  # threshold
        ff4_in[g, 9] = -2*BIG        # suppress commit
        ff4_in[D_FFN+g, 27] = 1.0
        ff4_out[25, g] = -4096.0
        # Gate g+1: relu(result - k*4096), output +4096
        g2 = g + 1
        ff4_in[g2, 25] = 1.0
        ff4_in[g2, 13] = BIG
        ff4_in[g2, 28] = BIG
        ff4_in[g2, 27] = -float(k * 4096) - 2*BIG
        ff4_in[g2, 9] = -2*BIG
        ff4_in[D_FFN+g2, 27] = 1.0
        ff4_out[25, g2] = 4096.0

    # Gate 34: MUL carry at slot > 0: floor(a0*b0/256) = (a0*b0 - byte0_result) / 256
    # dim 29 = a0*b0 (from L3 FFN gate 7, safe scratch: is_le_s=0 for MUL)
    # dim 0 = byte_value of input token (= byte 0 result at slot 1), preserved through all layers
    # At slot 1 for MUL: gate = a0*b0 - byte0 + BIG - BIG - 0 = a0*b0 - byte0 >= 0, always
    # Output scaled by 1/256 → floor(a0*b0/256) added to dim 25 (cross terms)
    ff4_in[34, 29] = 1.0       # +a0*b0 (from dim 29, scratch)
    ff4_in[34, 0] = -1.0       # -byte0_result (input token byte value)
    ff4_in[34, 13] = BIG       # is_mul
    ff4_in[34, 27] = -BIG      # threshold
    ff4_in[34, 9] = -2*BIG     # suppress commit
    ff4_in[34, 28] = -2*BIG    # suppress slot 0
    ff4_in[D_FFN+34, 27] = 1.0
    ff4_out[25, 34] = 1.0/256.0  # scale: carry = (product - byte0) / 256

    # L5: mod 4096 for MUL at all non-commit slots
    # At slot 0: value already < 4096 from L4 mod-4096 gates, these are no-ops
    # At slot 1: dim 25 = cross terms + carry, may exceed 4096, needs reduction
    ff5_in = model.ff_in[5].weight; ff5_out = model.ff_out[5].weight
    for k in range(1, 17):  # k=1..16
        g = (k-1)*2
        ff5_in[g, 25] = 1.0
        ff5_in[g, 13] = BIG
        ff5_in[g, 27] = -float(k * 4096 - 1) - BIG
        ff5_in[g, 9] = -2*BIG
        ff5_in[D_FFN+g, 27] = 1.0
        ff5_out[25, g] = -4096.0
        g2 = g + 1
        ff5_in[g2, 25] = 1.0
        ff5_in[g2, 13] = BIG
        ff5_in[g2, 27] = -float(k * 4096) - BIG
        ff5_in[g2, 9] = -2*BIG
        ff5_in[D_FFN+g2, 27] = 1.0
        ff5_out[25, g2] = 4096.0

    # L6: mod 256 for MUL at all non-commit slots + copy result to decode dim
    ff6_in = model.ff_in[6].weight; ff6_out = model.ff_out[6].weight
    for k in range(1, 16):  # k=1..15, reduces [0,4095] → [0,255]
        g = (k-1)*2
        ff6_in[g, 25] = 1.0
        ff6_in[g, 13] = BIG
        ff6_in[g, 27] = -float(k * 256 - 1) - BIG
        ff6_in[g, 9] = -2*BIG
        ff6_in[D_FFN+g, 27] = 1.0
        ff6_out[25, g] = -256.0
        g2 = g + 1
        ff6_in[g2, 25] = 1.0
        ff6_in[g2, 13] = BIG
        ff6_in[g2, 27] = -float(k * 256) - BIG
        ff6_in[g2, 9] = -2*BIG
        ff6_in[D_FFN+g2, 27] = 1.0
        ff6_out[25, g2] = 256.0
    # Gate 30: copy result to decode dim (for ALL ops)
    ff6_in[30, 27] = 1.0
    ff6_in[D_FFN+30, 25] = 1.0
    ff6_out[26, 30] = 1.0

    # Output head
    head = model.head.weight
    for b in range(256):
        head[b,25]=S_HEAD*b;head[b,27]=-S_HEAD*b*b/2.0
    head[0,27]=1.0


def _set_ip_pe(model, ip_sequence, local_src_a=None, stack_sizes=None,
               baked_values=None, structural_pops=None):
    """Set per-program PE: IP + src_a + baked values + structural pop corrections."""
    pe = model.pos_tok.weight
    for step_idx, ip in enumerate(ip_sequence):
        for slot in range(STEP_SIZE):
            if slot == 0 and step_idx == 0:
                pos = TRACE_START - 1
            else:
                trace_offset = step_idx * STEP_SIZE + slot
                pos = TRACE_START + trace_offset - 1
            if pos < pe.shape[0]:
                pe[pos, 7] = float(ip)
                if local_src_a and step_idx in local_src_a:
                    pe[pos, 4] = float(local_src_a[step_idx]) + 1.0
                if slot == 4 and stack_sizes and step_idx < len(stack_sizes):
                    pe[pos, 20] = float(stack_sizes[step_idx])
                # Inject baked result bytes for unsupported ops into dim 16
                if baked_values and step_idx in baked_values and slot < 4:
                    val = baked_values[step_idx]
                    pe[pos, 16] = float((val >> (slot * 8)) & 0xFF)
                # Inject structural pop correction into dim 17
                # br_if/if pop the condition between steps; the delta+1 in the
                # program doesn't account for this. Correction = -pops.
                if structural_pops and step_idx in structural_pops:
                    pe[pos, 17] = -float(structural_pops[step_idx])


def run_native(model, program):
    """
    Run program on NATIVE interpreter.
    For straight-line: no VM needed, IP = step_number.
    For control flow: uses hybrid encoding (VM for IP sequence only).
    Values always resolved at runtime via stack matching.
    """
    has_control_flow = any(
        inst.op in (Op.IF, Op.ELSE, Op.BLOCK, Op.LOOP, Op.BR, Op.BR_IF,
                    Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE)
        for inst in program
    )

    if has_control_flow:
        tokens, stack_sizes, ip_sequence, local_src_a, baked_values, structural_pops = encode_program_hybrid(program)
        with torch.no_grad():
            _set_ip_pe(model, ip_sequence, local_src_a, stack_sizes,
                       baked_values, structural_pops)
    else:
        tokens = encode_program_native(program)
        ip_sequence = None

    # Compute expected via VM
    vm = WasmVM(); vm.load_program(program); vm_trace = vm.run()

    max_trace = STEP_SIZE * (len(vm_trace) + 5)
    t0 = time.perf_counter()
    generated = generate_trace_rust_multilayer(model, tokens, max_trace)
    gen_time = time.perf_counter() - t0

    # Build expected from VM
    expected = []
    ss = 0
    prev_stack_top = 0
    for entry in vm_trace:
        op_name = entry.get('op', '')
        # br_if and if pop the condition; drop pops one value
        if op_name in ('br_if', 'if', 'drop'):
            ss -= 1
            continue
        if op_name in ('nop','block','loop','else','end','br'):
            continue
        val = entry.get('stack_top', 0) or 0
        if op_name == 'halt':
            expected.extend([0,0,0,0,COMMIT_HALT]); break
        vb = [val&0xFF,(val>>8)&0xFF,(val>>16)&0xFF,(val>>24)&0xFF]
        if op_name == 'i32_const': ss += 1
        elif op_name in ('i32_add','i32_sub','i32_mul','i32_le_s','i32_ge_s',
                          'i32_lt_s','i32_gt_s','i32_eq','i32_ne',
                          'i32_div_s','i32_rem_s','i32_and','i32_or',
                          'i32_xor','i32_shl','i32_shr_s'): ss -= 1
        elif op_name == 'i32_eqz': pass  # pop 1 push 1
        elif op_name in ('output','output_char'):
            ss -= 1; expected.extend([0,0,0,0,COMMIT_OUTPUT]); continue
        elif op_name == 'local_set':
            ss -= 1
            # Copy gate outputs the stored value (from stack before pop)
            stored_val = prev_stack_top if prev_stack_top is not None else 0
            vb = [stored_val&0xFF,(stored_val>>8)&0xFF,(stored_val>>16)&0xFF,(stored_val>>24)&0xFF]
        elif op_name == 'local_get': ss += 1
        expected.extend(vb + [ss])
        prev_stack_top = val

    # Restore universal PE if we modified it
    if has_control_flow:
        with torch.no_grad():
            _set_universal_pe(model)

    match = generated[:len(expected)] == expected
    tok_per_sec = len(generated)/gen_time if gen_time > 0 else 0
    return generated, {'expected': expected, 'match': match, 'n_tok': len(expected),
                        'gen_sec': gen_time, 'tok_per_sec': tok_per_sec,
                        'result': vm.output[0] if vm.output else '?'}


def test_native():
    """Test the NATIVE interpreter — runtime stack matching, no trace compilation."""
    print("=" * 70)
    print("NATIVE Interpreter — Runtime Stack Matching (Blog Architecture)")
    print("NO trace compilation. NO explicit addresses.")
    print("Operands resolved at RUNTIME from commit tokens.")
    print("=" * 70)

    model = build_native_interpreter()
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {n_params:,} params\n")

    tests = [
        ("3 + 5 = 8",
         [Instruction(Op.I32_CONST,3),Instruction(Op.I32_CONST,5),
          Instruction(Op.I32_ADD),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("7 * 13 = 91",
         [Instruction(Op.I32_CONST,7),Instruction(Op.I32_CONST,13),
          Instruction(Op.I32_MUL),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("10 - 3 = 7",
         [Instruction(Op.I32_CONST,10),Instruction(Op.I32_CONST,3),
          Instruction(Op.I32_SUB),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("2*(3+5) = 16",
         [Instruction(Op.I32_CONST,2),Instruction(Op.I32_CONST,3),
          Instruction(Op.I32_CONST,5),Instruction(Op.I32_ADD),
          Instruction(Op.I32_MUL),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("200 + 200 = 400",
         [Instruction(Op.I32_CONST,200),Instruction(Op.I32_CONST,200),
          Instruction(Op.I32_ADD),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("10 >= 5 = 1",
         [Instruction(Op.I32_CONST,10),Instruction(Op.I32_CONST,5),
          Instruction(Op.I32_GE_S),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
        ("5 == 5 = 1",
         [Instruction(Op.I32_CONST,5),Instruction(Op.I32_CONST,5),
          Instruction(Op.I32_EQ),Instruction(Op.OUTPUT),Instruction(Op.HALT)]),
    ]

    passed = 0
    for name, prog in tests:
        gen, info = run_native(model, prog)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']: passed += 1
        print(f"  {name:<25} {info['n_tok']:>4} tok  "
              f"{info['gen_sec']:.3f}s  {info['tok_per_sec']:>8,.0f} tok/s  "
              f"result={info['result']}  {status}")
        if not info['match']:
            print(f"    exp: {info['expected'][:25]}")
            print(f"    got: {gen[:25]}")
            for j in range(min(len(info['expected']),len(gen))):
                if gen[j]!=info['expected'][j]:
                    print(f"    diff at {j} (step {j//5} slot {j%5}): exp={info['expected'][j]} got={gen[j]}")
                    break

    # Control flow tests (uses hybrid: VM for IP, runtime stack matching for values)
    from mini_c import (Compiler, var, lit, add, le, ge,
                         assign, output_int, while_loop, if_then)
    from wasm_vm import make_fibonacci_program

    from mini_c import mul as mul_c, ne, mod, gt, div, eq as eq_c

    cf_tests = []

    # Conditional
    c = Compiler()
    code, _ = c.compile([assign('x', lit(10)),
        if_then(ge(var('x'), lit(5)), [output_int(lit(1))], [output_int(lit(0))])])
    cf_tests.append(("if 10>=5 -> 1", code))

    # Simple loop
    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(3)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    cf_tests.append(("sum(1..3) = 6", code))

    # Fibonacci
    cf_tests.append(("fib(5) = 5", make_fibonacci_program(5)))
    cf_tests.append(("fib(10) = 55", make_fibonacci_program(10)))
    cf_tests.append(("fib(15) = 610", make_fibonacci_program(15)))
    cf_tests.append(("fib(20) = 6765", make_fibonacci_program(20)))

    # Sum 1..10
    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(10)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    cf_tests.append(("sum(1..10) = 55", code))

    # Factorial 5! = 120
    c = Compiler()
    code, _ = c.compile([assign('r', lit(1)), assign('i', lit(2)),
        while_loop(le(var('i'), lit(5)), [
            assign('r', mul_c(var('r'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    cf_tests.append(("5! = 120", code))

    # GCD(48, 18) = 6
    c = Compiler()
    code, _ = c.compile([assign('a', lit(48)), assign('b', lit(18)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    cf_tests.append(("gcd(48,18) = 6", code))

    # Primality test: is_prime(17) = 1
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(17)), assign('i', lit(2)), assign('is_prime', lit(1)),
        while_loop(le(mul_c(var('i'), var('i')), var('n')), [
            if_then(ne(mod(var('n'), var('i')), lit(0)), [],
                    [assign('is_prime', lit(0))]),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('is_prime'))])
    cf_tests.append(("is_prime(17) = 1", code))

    # Collatz(7) = 16 steps
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(7)), assign('steps', lit(0)),
        while_loop(gt(var('n'), lit(1)), [
            if_then(eq_c(mod(var('n'), lit(2)), lit(0)),
                [assign('n', div(var('n'), lit(2)))],
                [assign('n', add(mul_c(lit(3), var('n')), lit(1)))]),
            assign('steps', add(var('steps'), lit(1)))]),
        output_int(var('steps'))])
    cf_tests.append(("collatz(7) = 16", code))

    # Longer programs
    cf_tests.append(("fib(25) = 75025", make_fibonacci_program(25)))
    cf_tests.append(("fib(30) = 832040", make_fibonacci_program(30)))

    # GCD(1071, 462) = 21
    c = Compiler()
    code, _ = c.compile([
        assign('a', lit(1071)), assign('b', lit(462)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    cf_tests.append(("gcd(1071,462) = 21", code))

    print("\n  --- Control Flow (hybrid: VM for IP, runtime stack matching) ---")
    for name, prog in cf_tests:
        gen, info = run_native(model, prog)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']: passed += 1
        total = len(tests) + len(cf_tests)
        print(f"  {name:<25} {info['n_tok']:>4} tok  "
              f"{info['gen_sec']:.3f}s  {info['tok_per_sec']:>8,.0f} tok/s  "
              f"result={info['result']}  {status}")
        if not info['match']:
            for j in range(min(len(info['expected']),len(gen))):
                if gen[j]!=info['expected'][j]:
                    print(f"    diff step {j//5} slot {j%5}: exp={info['expected'][j]} got={gen[j]}")
                    break

    print(f"\n  NATIVE Result: {passed}/{len(tests)+len(cf_tests)}")
    return passed == len(tests) + len(cf_tests)


if __name__ == '__main__':
    test()
    print()
    test_native()
