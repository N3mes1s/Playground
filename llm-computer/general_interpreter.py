"""
General WASM Interpreter compiled into fixed d_model=36 transformer weights.

ONE model runs ANY program. The program is passed as input tokens.
No per-program compilation — same weights for all programs.

Based on the SUBLEQ transformer approach (anadim/subleq-transformer):
- Quadratic attention for content-based addressing
- Program tokens encode instructions with explicit operand addresses
- Position embeddings are universal (function of position only)

Phase 1: CONST + ADD/SUB/MUL + OUTPUT + HALT, single-byte values.
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
MAX_INST = 32           # max instructions per program
INST_SIZE = 5           # tokens per instruction
PROG_LEN = MAX_INST * INST_SIZE  # 160
SEP_POS = PROG_LEN     # 160
TRACE_START = PROG_LEN + 1  # 161
MAX_SEQ = 500           # max sequence length

# Quadratic addressing scale
S_QUAD = 100.0  # high for sharp quadratic attention
S_HEAD = 50.0  # output head quadratic scale


@dataclass
class SimpleInstruction:
    """Instruction in explicit-address ISA (no stack)."""
    op: str        # 'const', 'add', 'sub', 'mul', 'output', 'halt', 'nop'
    immediate: int  # value for CONST
    src_a: int      # step index of operand A (for binary ops)
    src_b: int      # step index of operand B


def compile_wasm_to_simple(program: list[Instruction]) -> list[SimpleInstruction]:
    """
    Transform stack-based WASM to explicit-address instructions.
    Each instruction names its operand sources by step index.
    """
    stack = []  # stack of step indices
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

        else:
            # Unsupported opcode — skip
            pass

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
            # SEP predicts the first trace token (step 0, byte 0)
            pe[t, 4] = 1.0  # is_trace (for prediction)
            pe[t, 7] = 0.0  # step 0
            pe[t, 8] = 0.0  # byte 0

        else:
            # Trace region: PE at position t predicts the token at t+1
            # So encode metadata for position t+1
            next_trace_offset = (t + 1) - TRACE_START
            step = next_trace_offset // 4
            byte_idx = next_trace_offset % 4
            pe[t, 4] = 1.0  # is_trace
            pe[t, 7] = float(step)  # step number (for prediction target)
            pe[t, 8] = float(byte_idx)  # byte index (for prediction target)


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

    # Gate 0: fires for binary ops (is_add OR is_sub OR is_mul)
    ff0_in[0, 11] = 1.0  # is_add
    ff0_in[0, 12] = 1.0  # is_sub
    ff0_in[0, 13] = 1.0  # is_mul
    # Val 0: 2*S*(TRACE_START + 4*src_a_step + byte_idx)
    ff0_in[D_FFN + 0, 17] = 2 * S_QUAD * 4    # 8*S * src_a_step
    ff0_in[D_FFN + 0, 8] = 2 * S_QUAD          # 2*S * byte_idx
    ff0_in[D_FFN + 0, 27] = 2 * S_QUAD * TRACE_START  # constant
    ff0_out[19, 0] = 1.0  # -> dim 19 (Q target for op A)

    # Gate 1: same condition
    ff0_in[1, 11] = 1.0
    ff0_in[1, 12] = 1.0
    ff0_in[1, 13] = 1.0
    # Val 1: 2*S*(TRACE_START + 4*src_b_step + byte_idx)
    ff0_in[D_FFN + 1, 18] = 2 * S_QUAD * 4
    ff0_in[D_FFN + 1, 8] = 2 * S_QUAD
    ff0_in[D_FFN + 1, 27] = 2 * S_QUAD * TRACE_START
    ff0_out[20, 1] = 1.0  # -> dim 20 (Q target for op B)

    # Gate 2: for OUTPUT — fetch source value (like binary op A)
    ff0_in[2, 14] = 1.0  # is_output
    ff0_in[D_FFN + 2, 17] = 2 * S_QUAD * 4  # src_a_step (output source)
    ff0_in[D_FFN + 2, 8] = 2 * S_QUAD
    ff0_in[D_FFN + 2, 27] = 2 * S_QUAD * TRACE_START
    ff0_out[19, 2] = 1.0  # -> dim 19

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

    # Gate 0 (ADD) — only at byte 0
    ff1_in[0, 11] = 1.0    # is_add
    ff1_in[0, 8] = -2.0    # suppress at bytes 1-3
    ff1_in[D_FFN + 0, 23] = 1.0  # opA
    ff1_in[D_FFN + 0, 24] = 1.0  # opB
    ff1_out[25, 0] = 1.0

    # Gate 1 (CONST): only fires at byte 0 (byte_idx=0 means dim 8=0)
    # Use is_const AND (1 - byte_idx) as gate. But we can't AND without bias.
    # Simpler: the CONST gate reads is_const flag. It fires for ALL bytes.
    # But the val only has byte0 (dim 16). For bytes 1-3, dim 16 still has
    # the byte0 value (same fetch). We need byte 0 at position 0, byte 1 at
    # position 1 (which is 0 for small values).
    #
    # For Phase 1 (values < 256): bytes 1-3 are ALWAYS 0.
    # The model should output 0 for bytes 1-3. If no gate fires, dim 25 = 0
    # and the quadratic head decodes 0. So DON'T fire CONST gate for bytes 1-3.
    #
    # Trick: use dim 8 (byte_idx) to suppress. When byte_idx > 0, subtract
    # from the gate to make it negative.
    ff1_in[1, 10] = 1.0        # is_const flag
    ff1_in[1, 8] = -2.0        # subtract 2*byte_idx (negative for byte 1+)
    ff1_in[D_FFN + 1, 16] = 1.0  # immediate byte0
    ff1_out[25, 1] = 1.0

    # Gate 2 (SUB) — only at byte 0
    ff1_in[2, 12] = 1.0
    ff1_in[2, 8] = -2.0
    ff1_in[D_FFN + 2, 23] = 1.0
    ff1_in[D_FFN + 2, 24] = -1.0
    ff1_out[25, 2] = 1.0

    # Gate 3 (MUL) — bilinear, only at byte 0
    ff1_in[3, 23] = 1.0
    ff1_in[3, 13] = 1000.0
    ff1_in[3, 27] = -1000.0
    ff1_in[3, 8] = -2000.0  # suppress at bytes 1-3
    ff1_in[D_FFN + 3, 24] = 1.0
    ff1_out[25, 3] = 1.0

    # Gate 4 (OUTPUT) — outputs 0 for stack_top bytes (no gate = result stays 0)
    # The OUTPUT value bytes and marker are handled separately via the PE
    # For now, don't fire any gate for OUTPUT — result defaults to 0
    # (correct for the stack_top portion of the trace)

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

    # HALT and OUTPUT markers need special handling:
    # They only appear at specific positions (not at every byte of the step).
    # For Phase 1: suppress them — we verify the first 12 trace bytes
    # (the computation portion) are correct.
    # Phase 2 will handle the OUTPUT marker/value and HALT positions.
    # head[TraceVocab.HALT, 15] = 1e4
    # head[TraceVocab.OUTPUT, 14] = 1e4


def run_program(model, program: list[Instruction]) -> tuple[list[int], dict]:
    """
    Run a WASM program on the general interpreter.
    The SAME model instance handles ANY program.

    Returns: (generated_trace_tokens, info_dict)
    """
    # Compile WASM to simple ISA
    simple = compile_wasm_to_simple(program)

    # Encode as token sequence
    prog_tokens = encode_program(simple)

    # Get expected trace from VM
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run()
    tc = TraceCompiler()
    expected = tc.vm_trace_to_tokens(trace)

    # Generate trace autoregressively
    t0 = time.perf_counter()
    generated = _generate(model, prog_tokens, max_trace_tokens=len(expected) + 10)
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
    """Generate trace tokens autoregressively."""
    model.eval()
    sequence = list(prog_tokens)  # start with program + SEP
    trace_tokens = []

    with torch.no_grad():
        for _ in range(max_trace_tokens):
            input_ids = torch.tensor([sequence], dtype=torch.long)
            logits = model(input_ids)
            next_token = logits[0, -1].argmax().item()
            sequence.append(next_token)
            trace_tokens.append(next_token)

            if next_token == TraceVocab.HALT:
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

    tests = [
        ("3 + 5 = 8", make_addition_program(3, 5)),
        ("10 + 20 = 30", make_addition_program(10, 20)),
        ("7 * 13 = 91", make_multiplication_program(7, 13)),
        ("0 + 0 = 0", make_addition_program(0, 0)),
        ("50 + 50 = 100", make_addition_program(50, 50)),
    ]

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
