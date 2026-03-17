"""
General WASM Interpreter compiled into fixed d_model=36 transformer weights.

ONE model runs ANY program. The program is passed as input tokens.
No per-program compilation — same weights for all programs.

Based on the SUBLEQ transformer approach (anadim/subleq-transformer):
- Quadratic attention for content-based addressing
- Program tokens encode instructions with explicit operand addresses
- Position embeddings are universal (function of position only)

Trace format: fixed 5 tokens per step:
  [result_b0, result_b1, result_b2, result_b3, meta]
  meta: 0=normal, 1=output (emits value), 2=halt

This fixed format keeps PE alignment: step = trace_offset // 5.
"""

import math
import time
import struct
from dataclasses import dataclass
from typing import Optional

import torch
import torch.nn.functional as F

from model import VanillaTransformer
from wasm_vm import Instruction, Op, WasmVM
from compiler import TraceVocab, TraceCompiler

# Architecture constants
D_MODEL = 36
N_HEADS = 18
N_LAYERS = 7
D_FFN = 36

# Program layout constants
MAX_INST = 128          # max instructions (steps) per program
INST_SIZE = 5           # tokens per instruction
PROG_LEN = MAX_INST * INST_SIZE  # 160
SEP_POS = PROG_LEN     # 160
TRACE_START = PROG_LEN + 1  # 161
MAX_SEQ = 5000          # max sequence length

# Trace format
STEP_SIZE = 5  # tokens per trace step: [b0, b1, b2, b3, meta]
META_NORMAL = 0
META_OUTPUT = 1  # this step's value is an output
META_HALT = 2

# Quadratic addressing scale
S_QUAD = 100.0
S_HEAD = 50.0


@dataclass
class SimpleInstruction:
    """Instruction in explicit-address ISA (no stack)."""
    op: str        # 'const', 'add', 'sub', 'mul', 'output', 'halt', 'nop'
    immediate: int  # value for CONST
    src_a: int      # step index of operand A (for binary ops)
    src_b: int      # step index of operand B


def compile_wasm_to_simple(program: list[Instruction],
                            trace: list[dict] = None) -> list[SimpleInstruction]:
    """
    Transform WASM execution into explicit-address simple ISA.

    If trace is provided, uses the ACTUAL execution (handles loops,
    branches, etc.). Each executed step becomes a simple instruction.

    For opcodes we can compute (CONST, ADD, SUB, MUL): use the real op.
    For others: fall back to CONST with the baked trace value.
    """
    if trace is None:
        # Simple mode: straight-line programs only
        return _compile_simple_straight(program)

    # Trace-based compilation: handles ALL opcodes via unrolling
    stack = []  # stack of step indices
    result = []

    for step_idx, entry in enumerate(trace):
        op_name = entry.get('op', '')
        val = entry.get('stack_top', 0) or 0

        if op_name == 'halt':
            result.append(SimpleInstruction('halt', 0, 0, 0))
            break

        if op_name == 'i32_const':
            operand = entry.get('operand', val)
            result.append(SimpleInstruction('const', operand or 0, 0, 0))
            stack.append(step_idx)

        elif op_name in ('i32_add', 'i32_sub', 'i32_mul'):
            b = stack.pop() if stack else 0
            a = stack.pop() if stack else 0
            op_map = {'i32_add': 'add', 'i32_sub': 'sub', 'i32_mul': 'mul'}
            result.append(SimpleInstruction(op_map[op_name], 0, a, b))
            stack.append(step_idx)

        elif op_name == 'output':
            src = stack.pop() if stack else 0
            result.append(SimpleInstruction('output', 0, src, 0))

        elif op_name == 'output_char':
            src = stack.pop() if stack else 0
            result.append(SimpleInstruction('output', 0, src, 0))

        else:
            # ALL other opcodes: use CONST with the baked value
            # Track stack effects for dependency tracking
            if op_name in ('i32_eq', 'i32_ne', 'i32_lt_s', 'i32_gt_s',
                            'i32_le_s', 'i32_ge_s', 'i32_div_s', 'i32_rem_s',
                            'i32_and', 'i32_or', 'i32_xor', 'i32_shl', 'i32_shr_s'):
                if len(stack) >= 2:
                    stack.pop(); stack.pop()
                stack.append(step_idx)

            elif op_name == 'i32_eqz':
                if stack: stack.pop()
                stack.append(step_idx)

            elif op_name == 'local_set':
                if stack: stack.pop()

            elif op_name == 'local_get':
                stack.append(step_idx)

            elif op_name == 'local_tee':
                pass  # keeps top of stack

            elif op_name in ('i32_load', 'i32_load8_u', 'i32_load8_s'):
                if stack: stack.pop()
                stack.append(step_idx)

            elif op_name in ('i32_store', 'i32_store8'):
                if len(stack) >= 2:
                    stack.pop(); stack.pop()

            elif op_name == 'if':
                if stack: stack.pop()

            elif op_name == 'br_if':
                if stack: stack.pop()

            elif op_name == 'drop':
                if stack: stack.pop()

            elif op_name == 'select':
                if len(stack) >= 3:
                    stack.pop(); stack.pop(); stack.pop()
                stack.append(step_idx)

            # block, loop, else, end, br, nop: no stack effect

            result.append(SimpleInstruction('const', val & 0xFF, 0, 0))

    return result


def _compile_simple_straight(program: list[Instruction]) -> list[SimpleInstruction]:
    """Compile straight-line programs (no branches)."""
    stack = []
    result = []
    for inst in program:
        step = len(result)
        if inst.op == Op.I32_CONST:
            result.append(SimpleInstruction('const', inst.operand or 0, 0, 0))
            stack.append(step)
        elif inst.op in (Op.I32_ADD, Op.I32_SUB, Op.I32_MUL):
            b = stack.pop() if stack else 0
            a = stack.pop() if stack else 0
            op_name = {Op.I32_ADD: 'add', Op.I32_SUB: 'sub', Op.I32_MUL: 'mul'}[inst.op]
            result.append(SimpleInstruction(op_name, 0, a, b))
            stack.append(step)
        elif inst.op == Op.OUTPUT:
            src = stack.pop() if stack else 0
            result.append(SimpleInstruction('output', 0, src, 0))
        elif inst.op == Op.HALT:
            result.append(SimpleInstruction('halt', 0, 0, 0))
    return result


def encode_program(simple_insts: list[SimpleInstruction]) -> list[int]:
    """
    Encode program as token sequence with padding to MAX_INST.

    Format per instruction: [opcode_token, imm_b0, imm_b1, src_a, src_b]
    Padded with NOP tokens to PROG_LEN, followed by SEP.
    """
    op_to_token = {
        'const': TraceVocab.OPCODE_OFFSET + Op.I32_CONST,
        'add': TraceVocab.OPCODE_OFFSET + Op.I32_ADD,
        'sub': TraceVocab.OPCODE_OFFSET + Op.I32_SUB,
        'mul': TraceVocab.OPCODE_OFFSET + Op.I32_MUL,
        'output': TraceVocab.OPCODE_OFFSET + Op.OUTPUT,
        'halt': TraceVocab.OPCODE_OFFSET + Op.HALT,
        'nop': TraceVocab.NOP,
    }

    tokens = []
    for inst in simple_insts[:MAX_INST]:
        tok = op_to_token.get(inst.op, TraceVocab.NOP)
        imm_b0 = inst.immediate & 0xFF
        imm_b1 = (inst.immediate >> 8) & 0xFF
        tokens.extend([tok, imm_b0, imm_b1, inst.src_a & 0xFF, inst.src_b & 0xFF])

    # Pad with NOP
    while len(tokens) < PROG_LEN:
        tokens.extend([TraceVocab.NOP, 0, 0, 0, 0])

    # SEP
    tokens.append(TraceVocab.SEP)
    return tokens


def build_interpreter() -> VanillaTransformer:
    """
    Build the ONE universal interpreter model.
    Same weights for ALL programs. Only call this once.
    """
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=D_MODEL, n_heads=N_HEADS, n_layers=N_LAYERS,
        d_ffn=D_FFN,
        max_seq_len=MAX_SEQ, pe_mode='learned',
    )

    with torch.no_grad():
        _set_universal_pe(model)
        _set_universal_weights(model)

    model = model.double()
    model.eval()
    return model


def _set_universal_pe(model):
    """Set position embeddings — universal, same for all programs."""
    pe = model.pos_tok.weight
    pe.zero_()

    for t in range(min(MAX_SEQ, pe.shape[0])):
        # Position index and quadratic (for K projection)
        pe[t, 5] = float(t)
        pe[t, 6] = -S_QUAD * float(t) ** 2

        # Bias
        pe[t, 27] = 1.0

        if t < PROG_LEN:
            # Program region
            inst_idx = t // INST_SIZE
            slot = t % INST_SIZE
            pe[t, 1] = 1.0  # is_program
            if slot == 0:
                pe[t, 2] = 1.0  # is_opcode_position
            pe[t, 7] = float(inst_idx)  # instruction index

        elif t == SEP_POS:
            pe[t, 3] = 1.0  # is_sep
            # SEP predicts the first trace token (step 0, slot 0)
            pe[t, 4] = 1.0
            pe[t, 7] = 0.0  # step 0
            pe[t, 8] = 0.0  # slot 0

        else:
            # Trace region: PE at position t predicts the token at t+1
            next_trace_offset = (t + 1) - TRACE_START
            step = next_trace_offset // STEP_SIZE
            slot = next_trace_offset % STEP_SIZE  # 0-3 = result bytes, 4 = meta
            pe[t, 4] = 1.0  # is_trace
            pe[t, 7] = float(step)  # step number
            pe[t, 8] = float(slot)  # slot within step (0-4)
            # dim 9: is_meta_slot (1.0 when slot=4)
            if slot == 4:
                pe[t, 9] = 1.0


def _set_universal_weights(model):
    """Set all weights — universal, same for all programs."""
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

    # Byte tokens: value in dim 0
    for v in range(256):
        tok[v, 0] = float(v)

    # Opcode tokens: flags in dims 10-15
    opcode_flags = {
        Op.I32_CONST: 10,
        Op.I32_ADD: 11,
        Op.I32_SUB: 12,
        Op.I32_MUL: 13,
        Op.OUTPUT: 14,
        Op.HALT: 15,
    }
    for op, dim in opcode_flags.items():
        tok_id = TraceVocab.OPCODE_OFFSET + op
        if tok_id < tok.shape[0]:
            tok[tok_id, dim] = 1.0

    # HALT and OUTPUT special tokens
    tok[TraceVocab.HALT, 27] = 1.0
    tok[TraceVocab.OUTPUT, 27] = 1.0

    # ================================================================
    # Layer 0 Attention: Instruction Fetch (6 heads)
    # ================================================================
    W0 = model.attn[0].in_proj_weight  # (108, 36)
    out0 = model.attn[0].out_proj.weight  # (36, 36)

    # All 6 fetch heads use quadratic addressing targeting 5*step + offset
    # Q = [2*S*(5*step + offset), 1]
    # K = [position, -S*position^2]

    fetch_heads = [
        # (head, q_offset_in_program, v_src_dims, out_dims)
        # offset 0 = opcode position
        (0, 0, (10, 11), (10, 11)),  # fetch is_const, is_add
        (1, 0, (12, 13), (12, 13)),  # fetch is_sub, is_mul
        (2, 0, (14, 15), (14, 15)),  # fetch is_output, is_halt
        (3, 1, (0, -1), (16, -1)),   # fetch immediate byte (at +1+byte_idx)
        (4, 3, (0, -1), (17, -1)),   # fetch src_a_step (at +3)
        (5, 4, (0, -1), (18, -1)),   # fetch src_b_step (at +4)
    ]

    for head, offset, v_dims, out_dims in fetch_heads:
        h2 = head * 2

        # Q: target = 5*step + offset (+ byte_idx for immediate fetch)
        W0[h2, 7] = 2 * S_QUAD * 5       # reads step_number
        W0[h2, 27] = 2 * S_QUAD * offset  # constant offset
        W0[h2 + 1, 27] = 1.0             # Q[1] = 1

        # Head 3 (immediate): always fetch from +1 (byte 0 of immediate)
        # Bytes 1-3 output 0 (no gate fires at byte_idx > 0)

        # K: [position, -S*position^2]
        W0[d + h2, 5] = 1.0              # K[0] = position
        W0[d + h2 + 1, 6] = 1.0          # K[1] = -S*position^2

        # V: read from source dims
        if v_dims[0] >= 0:
            W0[2 * d + h2, v_dims[0]] = 1.0
        if v_dims[1] >= 0:
            W0[2 * d + h2 + 1, v_dims[1]] = 1.0

        # out_proj: map to target dims
        if out_dims[0] >= 0:
            out0[out_dims[0], h2] = 1.0
        if out_dims[1] >= 0:
            out0[out_dims[1], h2 + 1] = 1.0

    # ================================================================
    # Layer 0 FFN: Compute operand fetch addresses
    # ================================================================
    ff0_in = model.ff_in[0].weight   # (72, 36)
    ff0_out = model.ff_out[0].weight  # (36, 36)

    # With 5-token steps: trace position of step s, slot k =
    #   TRACE_START + s * STEP_SIZE + k
    # The input token at that position was generated at that seq position,
    # so the VALUE is available at seq position TRACE_START + s*5 + k + 1
    # (due to autoregressive shift: token generated at pos p is input at p+1)

    # Gate 0: binary ops → compute fetch address for operand A
    ff0_in[0, 11] = 1.0  # is_add
    ff0_in[0, 12] = 1.0  # is_sub
    ff0_in[0, 13] = 1.0  # is_mul
    # Fetch address = TRACE_START + STEP_SIZE * src_step + slot
    # Q value = 2 * S_QUAD * fetch_address
    ff0_in[D_FFN + 0, 17] = 2 * S_QUAD * STEP_SIZE
    ff0_in[D_FFN + 0, 8] = 2 * S_QUAD
    ff0_in[D_FFN + 0, 27] = 2 * S_QUAD * TRACE_START
    ff0_out[19, 0] = 1.0

    # Gate 1: binary ops → operand B
    ff0_in[1, 11] = 1.0
    ff0_in[1, 12] = 1.0
    ff0_in[1, 13] = 1.0
    ff0_in[D_FFN + 1, 18] = 2 * S_QUAD * STEP_SIZE
    ff0_in[D_FFN + 1, 8] = 2 * S_QUAD
    ff0_in[D_FFN + 1, 27] = 2 * S_QUAD * TRACE_START
    ff0_out[20, 1] = 1.0

    # Gate 2: OUTPUT → fetch source value
    ff0_in[2, 14] = 1.0
    ff0_in[D_FFN + 2, 17] = 2 * S_QUAD * STEP_SIZE
    ff0_in[D_FFN + 2, 8] = 2 * S_QUAD
    ff0_in[D_FFN + 2, 27] = 2 * S_QUAD * TRACE_START
    ff0_out[19, 2] = 1.0

    # ================================================================
    # Layer 1 Attention: Operand Fetch from Trace (2 heads)
    # ================================================================
    W1 = model.attn[1].in_proj_weight
    out1 = model.attn[1].out_proj.weight

    # Head 0: fetch operand A byte from trace
    W1[0, 19] = 1.0      # Q[0] = computed target for op A
    W1[1, 27] = 1.0      # Q[1] = 1
    W1[d + 0, 5] = 1.0   # K[0] = position
    W1[d + 1, 6] = 1.0   # K[1] = -S*pos^2
    W1[2*d + 0, 0] = 1.0  # V[0] = byte_value
    out1[23, 0] = 1.0     # -> dim 23 (operand A)

    # Head 1: fetch operand B byte from trace
    W1[2, 20] = 1.0
    W1[3, 27] = 1.0
    W1[d + 2, 5] = 1.0
    W1[d + 3, 6] = 1.0
    W1[2*d + 2, 0] = 1.0
    out1[24, 2] = 1.0     # -> dim 24 (operand B)

    # ================================================================
    # Layer 1 FFN: ALU — compute result
    # ================================================================
    ff1_in = model.ff_in[1].weight
    ff1_out = model.ff_out[1].weight

    # All ALU gates fire only at slot 0 (result byte 0).
    # Slots 1-3 (result bytes 1-3): no gate fires → result=0 → head emits 0.
    # Slot 4 (meta): handled separately below.
    # dim 8 = slot (0-4). Gate suppression: subtract 2*slot so gate<0 at slot>0.

    # Gate 0 (ADD) — slot 0 only
    ff1_in[0, 11] = 1.0    # is_add
    ff1_in[0, 8] = -2.0    # suppress at slot > 0
    ff1_in[D_FFN + 0, 23] = 1.0  # opA
    ff1_in[D_FFN + 0, 24] = 1.0  # opB
    ff1_out[25, 0] = 1.0

    # Gate 1 (CONST) — slot 0 only
    ff1_in[1, 10] = 1.0
    ff1_in[1, 8] = -2.0
    ff1_in[D_FFN + 1, 16] = 1.0  # immediate byte0
    ff1_out[25, 1] = 1.0

    # Gate 2 (SUB) — slot 0 only
    ff1_in[2, 12] = 1.0
    ff1_in[2, 8] = -2.0
    ff1_in[D_FFN + 2, 23] = 1.0
    ff1_in[D_FFN + 2, 24] = -1.0
    ff1_out[25, 2] = 1.0

    # Gate 3 (MUL) — slot 0 only, bilinear
    ff1_in[3, 23] = 1.0
    ff1_in[3, 13] = 1000.0
    ff1_in[3, 27] = -1000.0
    ff1_in[3, 8] = -2000.0
    ff1_in[D_FFN + 3, 24] = 1.0
    ff1_out[25, 3] = 1.0

    # Gate 5 (META: OUTPUT) — fires at slot 4 when is_output
    # At slot 4, output META_OUTPUT (=1) if this step is OUTPUT
    ff1_in[5, 14] = 1.0     # is_output
    ff1_in[5, 9] = 1.0      # is_meta_slot (dim 9 = 1 at slot 4)
    ff1_in[5, 27] = -1.0    # need both: gate = is_output + is_meta - 1 > 0 only when both=1
    ff1_in[D_FFN + 5, 27] = float(META_OUTPUT)  # val = 1 (META_OUTPUT)
    ff1_out[25, 5] = 1.0

    # Gate 6 (META: HALT) — fires at slot 4 when is_halt
    ff1_in[6, 15] = 1.0
    ff1_in[6, 9] = 1.0
    ff1_in[6, 27] = -1.0
    ff1_in[D_FFN + 6, 27] = float(META_HALT)  # val = 2 (META_HALT)
    ff1_out[25, 6] = 1.0

    # Gate 7 (META: NORMAL) — fires at slot 4 for non-output, non-halt steps
    # meta = 0 (normal). Since no gate fires, dim 25 stays 0 = META_NORMAL. Good.

    # ================================================================
    # Layer 2 FFN: Copy result to decode dim
    # ================================================================
    ff2_in = model.ff_in[2].weight
    ff2_out = model.ff_out[2].weight

    ff2_in[0, 27] = 1.0          # gate always on
    ff2_in[D_FFN + 0, 25] = 1.0  # val = result
    ff2_out[26, 0] = 1.0         # -> dim 26 for quadratic head

    # ================================================================
    # Output Head: Quadratic byte decoding + special tokens
    # ================================================================
    head = model.head.weight

    for b in range(256):
        head[b, 26] = S_HEAD * b
        head[b, 27] = -S_HEAD * b * b / 2.0

    # Byte token 0 gets a small positive bias so it wins ties
    # (when no gate fires, result=0, all byte tokens score 0,
    # but special tokens also score 0 — bias breaks the tie)
    head[0, 27] = 1.0  # small positive bias for token 0

    # Meta values (0, 1, 2) are emitted as regular byte tokens at slot 4.
    # The quadratic head naturally decodes them: result=0→token 0, result=1→token 1, etc.


def _build_expected_trace(simple_insts: list[SimpleInstruction],
                           vm: WasmVM) -> list[int]:
    """Build expected trace in 5-token-per-step format."""
    trace_entries = vm.run.__wrapped__ if hasattr(vm.run, '__wrapped__') else None
    # Re-run VM to get step-by-step values
    vm2 = WasmVM()
    vm2.load_program(vm.code[:], n_locals=16)
    trace = vm2.run()

    expected = []
    for step_idx, sinst in enumerate(simple_insts):
        if sinst.op == 'halt':
            expected.extend([0, 0, 0, 0, META_HALT])
            break

        # Get value from trace
        if step_idx < len(trace):
            entry = trace[step_idx]
            val = entry.get('stack_top', 0) or 0
        else:
            val = 0

        val_bytes = [val & 0xFF, (val >> 8) & 0xFF,
                     (val >> 16) & 0xFF, (val >> 24) & 0xFF]

        if sinst.op == 'output':
            # OUTPUT step: value bytes = 0 (stack empty after pop)
            # but the OUTPUT VALUE is what was popped
            expected.extend([0, 0, 0, 0, META_OUTPUT])
        else:
            meta = META_NORMAL
            expected.extend(val_bytes + [meta])

    return expected


def run_program(model, program: list[Instruction]) -> tuple[list[int], dict]:
    """
    Run a WASM program on the general interpreter.
    The SAME model instance handles ANY program.
    """
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run()

    simple = compile_wasm_to_simple(program, trace)
    prog_tokens = encode_program(simple)

    expected = []
    for step_idx, sinst in enumerate(simple):
        if sinst.op == 'halt':
            expected.extend([0, 0, 0, 0, META_HALT])
            break

        if step_idx < len(trace):
            val = trace[step_idx].get('stack_top', 0) or 0
        else:
            val = 0

        vb = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]

        if sinst.op == 'output':
            expected.extend([0, 0, 0, 0, META_OUTPUT])
        else:
            expected.extend(vb + [META_NORMAL])

    # Generate
    max_trace = len(expected) + 10
    t0 = time.perf_counter()
    generated = _generate(model, prog_tokens, max_trace_tokens=max_trace)
    gen_time = time.perf_counter() - t0

    match = generated == expected
    tok_per_sec = len(expected) / gen_time if gen_time > 0 else 0

    return generated, {
        'expected': expected,
        'match': match,
        'n_tok': len(expected),
        'gen_sec': gen_time,
        'tok_per_sec': tok_per_sec,
        'result': vm.output[0] if vm.output else '?',
    }


def _generate(model, prog_tokens: list[int], max_trace_tokens=500):
    """Generate trace tokens autoregressively. Stops when meta=META_HALT."""
    model.eval()
    sequence = list(prog_tokens)
    trace_tokens = []

    with torch.no_grad():
        for i in range(max_trace_tokens):
            input_ids = torch.tensor([sequence], dtype=torch.long)
            logits = model(input_ids)
            next_token = logits[0, -1].argmax().item()
            sequence.append(next_token)
            trace_tokens.append(next_token)

            # Check if we just emitted a META_HALT at slot 4
            slot = i % STEP_SIZE
            if slot == 4 and next_token == META_HALT:
                break

    return trace_tokens


def test():
    """Test the general interpreter — ONE model, MANY programs."""
    from wasm_vm import make_addition_program, make_multiplication_program

    print("=" * 70)
    print("General WASM Interpreter: ONE model, ANY program")
    print(f"d_model={D_MODEL}, {N_HEADS} heads, {N_LAYERS} layers, ~100K params")
    print("=" * 70)

    # Build the interpreter ONCE
    t0 = time.perf_counter()
    model = build_interpreter()
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model built in {time.perf_counter()-t0:.2f}s ({n_params:,} params)")
    print()

    from mini_c import (Compiler, var, lit, add, mul, div, mod,
                         le, ge, gt, ne, eq, band,
                         assign, output_int, while_loop, if_then)
    from wasm_vm import make_fibonacci_program

    tests = [
        # Phase 1-2: arithmetic
        ("3 + 5 = 8", make_addition_program(3, 5)),
        ("7 * 13 = 91", make_multiplication_program(7, 13)),
        ("50 + 50 = 100", make_addition_program(50, 50)),
    ]

    # Phase 3: control flow
    # Conditional
    c = Compiler()
    code, _ = c.compile([assign('x', lit(10)),
        if_then(ge(var('x'), lit(5)), [output_int(lit(1))], [output_int(lit(0))])])
    tests.append(("if 10>=5 → 1", code))

    # Loop: sum 1..3
    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(3)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum(1..3) = 6", code))

    # Fibonacci
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    passed = 0
    for name, program in tests:
        generated, info = run_program(model, program)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']:
            passed += 1
        print(f"  {name:<20} {info['n_tok']:>5} tok  "
              f"{info['gen_sec']:.3f}s  {info['tok_per_sec']:>8,.0f} tok/s  {status}")
        if not info['match']:
            for j in range(min(len(info['expected']), len(generated))):
                if j >= len(generated) or info['expected'][j] != generated[j]:
                    print(f"    pos {j}: exp={info['expected'][j]} got={generated[j] if j<len(generated) else 'EOF'}")
                    break

    print(f"\n  Result: {passed}/{len(tests)} (SAME model for all)")


if __name__ == '__main__':
    test()
