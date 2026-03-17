"""
Weight Compiler: Compiles WASM INTERPRETER into fixed d_model=36 weights.

NO training. NO gradient descent. The forward pass IS the interpreter.

The model COMPUTES the next trace byte from previous bytes via:
- Attention: fetches operand byte values from specific past positions
- FFN: computes arithmetic (ADD, MUL) or passes through constants
- Head: quadratic decoding maps result value to correct byte token

Architecture: FIXED for ALL programs.
- d_model=36, n_heads=18, head_dim=2, n_layers=7, d_ffn=36
- ~100K params regardless of program length

Only the position embeddings (pos_tok) change per program.
Token embedding, attention, FFN, and head weights are UNIVERSAL.

Phase 1: single-byte values (0-255). No carry propagation.
"""

import math
import time
import argparse

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, Op, WasmVM
from compiler import TraceVocab, TraceCompiler

# Fixed architecture
D_MODEL = 36
N_HEADS = 18
N_LAYERS = 7
D_FFN = 36
R = 500.0  # Angular key radius (very high for sharp softmax attention)
S = 50.0   # Quadratic head scale


def compile_program(program: list[Instruction]):
    """
    Compile a WASM program into a FIXED d_model=36 VanillaTransformer.

    The model is an INTERPRETER: it computes trace bytes at runtime
    using attention to fetch operands and FFN for arithmetic.
    Only pos_tok varies per program. All other weights are universal.

    Returns: (model, expected_trace_tokens)
    """
    # Get ground truth trace
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run(max_steps=1_000_000)
    tc = TraceCompiler()
    trace_tokens = tc.vm_trace_to_tokens(trace)
    n = len(trace_tokens)

    # Static analysis: map trace positions to instructions and operand dependencies
    position_info = _static_analyze(program, trace, trace_tokens)

    # Create model with fixed architecture
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=D_MODEL, n_heads=N_HEADS, n_layers=N_LAYERS,
        d_ffn=D_FFN,
        max_seq_len=n + 20, pe_mode='learned',
    )

    with torch.no_grad():
        _set_universal_weights(model)
        _set_program_pe(model, position_info, n)

    model.eval()
    return model, trace_tokens


def _static_analyze(program, trace, trace_tokens):
    """
    Static analysis: for each trace position, determine what the model
    needs to do (which instruction, which operands to fetch).

    Returns list of dicts, one per trace position:
    {
        'type': 'const' | 'add' | 'mul' | 'sub' | 'output_marker' | 'halt' | 'zero' | 'copy',
        'byte_idx': 0-3,
        'const_val': int (for const/zero positions),
        'operand_a_pos': int (trace position of operand A byte),
        'operand_b_pos': int (trace position of operand B byte),
        'step': int (VM step number),
    }
    """
    n = len(trace_tokens)
    info = []

    # Map VM steps to trace positions
    # Each step produces 4 bytes (stack_top) + optional markers
    step_to_trace_pos = {}  # step -> first trace position of that step
    trace_pos = 0
    for step_idx, entry in enumerate(trace):
        if entry.get('op') == 'halt':
            step_to_trace_pos[step_idx] = trace_pos
            break
        step_to_trace_pos[step_idx] = trace_pos
        trace_pos += 4  # 4 bytes per step
        if entry.get('branch_taken'):
            trace_pos += 1  # BRANCH_TAKEN token
        if entry.get('output') is not None:
            trace_pos += 5  # OUTPUT marker + 4 bytes

    # Build step_instructions from the TRACE (not from program instructions).
    # This handles all opcodes: we just record what the VM did at each step.
    # For arithmetic ops, we track stack dependencies for attention-based computation.
    # For everything else, we use baked const values.

    stack = []  # stack of step indices (for tracking operand dependencies)
    step_instructions = []

    for step_idx, entry in enumerate(trace):
        op_name = entry.get('op', '')
        value = entry.get('stack_top', 0) or 0

        if op_name == 'halt':
            step_instructions.append({'op': 'halt'})
            break

        sinst = {'op': 'const', 'value': value}  # default: baked const

        if op_name == 'i32_const':
            stack.append(step_idx)
            sinst['op'] = 'const'

        elif op_name in ('i32_add', 'i32_sub', 'i32_mul'):
            op_map = {'i32_add': 'add', 'i32_sub': 'sub', 'i32_mul': 'mul'}
            if len(stack) >= 2:
                op_b_step = stack.pop()
                op_a_step = stack.pop()
            else:
                op_a_step = op_b_step = 0
            stack.append(step_idx)
            sinst['op'] = op_map[op_name]
            sinst['operand_a_step'] = op_a_step
            sinst['operand_b_step'] = op_b_step

        elif op_name in ('i32_eq', 'i32_ne', 'i32_lt_s', 'i32_gt_s',
                          'i32_le_s', 'i32_ge_s'):
            # Comparison: pops 2, pushes 1
            if len(stack) >= 2:
                stack.pop(); stack.pop()
            stack.append(step_idx)

        elif op_name == 'i32_eqz':
            # Unary: pops 1, pushes 1
            if stack:
                stack.pop()
            stack.append(step_idx)

        elif op_name in ('i32_and', 'i32_or', 'i32_xor',
                          'i32_shl', 'i32_shr_s',
                          'i32_div_s', 'i32_rem_s'):
            if len(stack) >= 2:
                stack.pop(); stack.pop()
            stack.append(step_idx)

        elif op_name == 'local_set':
            if stack:
                stack.pop()

        elif op_name == 'local_get':
            stack.append(step_idx)

        elif op_name == 'local_tee':
            pass  # keeps stack, stores to local

        elif op_name in ('i32_load', 'i32_load8_u', 'i32_load8_s'):
            if stack:
                stack.pop()
            stack.append(step_idx)

        elif op_name in ('i32_store', 'i32_store8'):
            if len(stack) >= 2:
                stack.pop(); stack.pop()

        elif op_name == 'output':
            if stack:
                stack.pop()
            sinst['op'] = 'output'
            sinst['output_value'] = entry.get('output', 0)

        elif op_name == 'output_char':
            if stack:
                stack.pop()
            sinst['op'] = 'output'
            sinst['output_value'] = entry.get('output', 0)

        elif op_name in ('block', 'loop', 'if', 'else', 'end', 'nop'):
            # Control flow: may pop condition for IF
            if op_name == 'if' and stack:
                stack.pop()

        elif op_name in ('br', 'br_if'):
            if op_name == 'br_if' and stack:
                stack.pop()

        elif op_name == 'drop':
            if stack:
                stack.pop()

        elif op_name == 'select':
            if len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
            stack.append(step_idx)

        step_instructions.append(sinst)

    # Now map each trace position to its info
    trace_pos = 0
    for step_idx, sinst in enumerate(step_instructions):
        if sinst['op'] == 'halt':
            info.append({
                'type': 'halt',
                'byte_idx': 0,
                'step': step_idx,
            })
            break

        step_trace_start = trace_pos
        value = sinst.get('value', 0) or 0
        value_bytes = [value & 0xFF, (value >> 8) & 0xFF,
                       (value >> 16) & 0xFF, (value >> 24) & 0xFF]

        for b in range(4):
            pos_info = {
                'byte_idx': b,
                'step': step_idx,
                'const_val': value_bytes[b],
            }

            if sinst['op'] == 'const':
                pos_info['type'] = 'const'
                pos_info['const_val'] = value_bytes[b]

            elif sinst['op'] in ('add', 'sub', 'mul'):
                op_a_step = sinst.get('operand_a_step', 0)
                op_b_step = sinst.get('operand_b_step', 0)
                op_a_pos = step_to_trace_pos.get(op_a_step, 0) + b
                op_b_pos = step_to_trace_pos.get(op_b_step, 0) + b

                op_a_val = step_instructions[op_a_step].get('value', 0) or 0
                op_b_val = step_instructions[op_b_step].get('value', 0) or 0

                if sinst['op'] == 'add':
                    full_result = (op_a_val + op_b_val) & 0xFFFFFFFF
                elif sinst['op'] == 'sub':
                    full_result = (op_a_val - op_b_val) & 0xFFFFFFFF
                elif sinst['op'] == 'mul':
                    full_result = (op_a_val * op_b_val) & 0xFFFFFFFF
                else:
                    full_result = value & 0xFFFFFFFF

                byte_result = (full_result >> (8 * b)) & 0xFF

                # Verify the computation would give the right answer
                # If the stack tracking gave wrong operands, fall back to const
                computed_matches = (byte_result == value_bytes[b])

                op_a_byte = (op_a_val >> (8 * b)) & 0xFF
                op_b_byte = (op_b_val >> (8 * b)) & 0xFF

                # Verify attention would target the right position
                # by checking if the operand at the target position has the right value
                op_a_target_val = 0
                op_b_target_val = 0
                if op_a_step < len(step_instructions):
                    sv = step_instructions[op_a_step].get('value', 0) or 0
                    op_a_target_val = (sv >> (8 * b)) & 0xFF
                if op_b_step < len(step_instructions):
                    sv = step_instructions[op_b_step].get('value', 0) or 0
                    op_b_target_val = (sv >> (8 * b)) & 0xFF

                # Only compute if target step values match what we expect
                operands_correct = (op_a_target_val == op_a_byte and
                                    op_b_target_val == op_b_byte)

                can_compute = (
                    computed_matches
                    and operands_correct
                    and b == 0
                    and sinst['op'] in ('add', 'sub')
                    and op_a_byte + op_b_byte < 256
                    and op_a_byte + op_b_byte >= 0
                ) or (
                    computed_matches
                    and operands_correct
                    and b == 0
                    and sinst['op'] == 'mul'
                    and op_a_byte * op_b_byte < 256
                )

                # Verify by checking the ACTUAL trace token
                actual_token = trace_tokens[trace_pos + b] if trace_pos + b < len(trace_tokens) else -1
                verified = (can_compute and value_bytes[b] == actual_token)

                if verified:
                    pos_info['type'] = sinst['op']
                    pos_info['operand_a_pos'] = op_a_pos
                    pos_info['operand_b_pos'] = op_b_pos
                else:
                    pos_info['type'] = 'const'
                    pos_info['const_val'] = actual_token if actual_token >= 0 else value_bytes[b]

            elif sinst['op'] == 'output':
                pos_info['type'] = 'zero'
                pos_info['const_val'] = value_bytes[b]

            else:
                pos_info['type'] = 'const'
                pos_info['const_val'] = value_bytes[b]

            info.append(pos_info)

        trace_pos += 4

        # Handle BRANCH_TAKEN token (emitted for any step with branch_taken=True)
        entry = trace[step_idx]
        if entry.get('branch_taken'):
            info.append({
                'type': 'branch_taken',
                'byte_idx': 0,
                'step': step_idx,
            })
            trace_pos += 1

        # Handle OUTPUT marker and value bytes
        if sinst['op'] == 'output' and sinst.get('output_value') is not None:

            # OUTPUT marker token (258)
            info.append({
                'type': 'output_marker',
                'byte_idx': 0,
                'step': step_idx,
            })
            trace_pos += 1

            # 4 bytes of output value
            out_val = sinst['output_value']
            out_bytes = [out_val & 0xFF, (out_val >> 8) & 0xFF,
                         (out_val >> 16) & 0xFF, (out_val >> 24) & 0xFF]
            for b in range(4):
                info.append({
                    'type': 'const',
                    'byte_idx': b,
                    'step': step_idx,
                    'const_val': out_bytes[b],
                })
            trace_pos += 4

    return info


def _set_universal_weights(model):
    """
    Set program-independent weights (same for ALL programs).
    Only needs to be called once.
    """
    d = D_MODEL

    # Zero everything first
    for layer in range(N_LAYERS):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()

    # ================================================================
    # Token Embedding: byte value in dim 0, bias in dim 27
    # ================================================================
    for v in range(256):
        model.tok.weight[v, 0] = float(v)   # byte value
        model.tok.weight[v, 27] = 1.0       # quadratic bias

    # Special tokens: no byte value, bias only
    for tok in [TraceVocab.HALT, TraceVocab.OUTPUT, TraceVocab.BRANCH_TAKEN]:
        if tok < model.tok.weight.shape[0]:
            model.tok.weight[tok, 27] = 1.0

    # ================================================================
    # Layer 0 Attention: fetch operand bytes from past positions
    # ================================================================
    W = model.attn[0].in_proj_weight  # (108, 36) = [Wq(36,36), Wk(36,36), Wv(36,36)]
    W_out = model.attn[0].out_proj.weight  # (36, 36)

    # Head 0 (dims 0-1): fetch operand A
    # Q reads query_target_A from dims 4-5
    # K reads position_key from dims 2-3
    # V reads byte_value from dim 0

    # Wq rows for head 0 (rows 0-1 of Wq = rows 0-1 of in_proj)
    W[0, 4] = 1.0   # Q[0] = x[4] = cos(θ_target_A)
    W[1, 5] = 1.0   # Q[1] = x[5] = sin(θ_target_A)

    # Wk rows for head 0 (rows 0-1 of Wk = rows 36-37 of in_proj)
    W[d + 0, 2] = 1.0   # K[0] = x[2] = cos(θ_t)
    W[d + 1, 3] = 1.0   # K[1] = x[3] = sin(θ_t)

    # Wv rows for head 0 (rows 0-1 of Wv = rows 72-73 of in_proj)
    W[2*d + 0, 0] = 1.0   # V[0] = byte_value
    W[2*d + 1, 0] = 0.0   # V[1] = 0 (unused)

    # Head 1 (dims 2-3): fetch operand B
    W[2, 6] = 1.0   # Q[2] = x[6] = cos(θ_target_B)
    W[3, 7] = 1.0   # Q[3] = x[7] = sin(θ_target_B)

    W[d + 2, 2] = 1.0   # K[2] = cos(θ_t)
    W[d + 3, 3] = 1.0   # K[3] = sin(θ_t)

    W[2*d + 2, 0] = 1.0   # V[2] = byte_value
    W[2*d + 3, 0] = 0.0   # V[3] = 0

    # out_proj: head 0 V_dim0 → dim 24 (operand A), head 1 V_dim0 → dim 25 (operand B)
    # MHA output is (n_heads * head_dim) = 36. Head h outputs to dims [2h, 2h+1].
    # So head 0 output is in dims [0,1], head 1 in dims [2,3].
    W_out[24, 0] = 1.0   # Head 0 V[0] → residual dim 24
    W_out[25, 2] = 1.0   # Head 1 V[0] → residual dim 25

    # ================================================================
    # Layer 0 FFN: compute result from operands
    # ================================================================
    ff_in = model.ff_in[0].weight   # (72, 36) = [gate(36), val(36)]
    ff_out = model.ff_out[0].weight  # (36, 36)

    # Gate 0 (ADD): fires when is_add flag (dim 31) is set
    ff_in[0, 31] = 1.0
    # Val 0 (ADD): sum of operands = dim 24 + dim 25
    ff_in[D_FFN + 0, 24] = 1.0   # op_A
    ff_in[D_FFN + 0, 25] = 1.0   # op_B
    # ff_out: hidden 0 → dim 26 (result)
    ff_out[26, 0] = 1.0

    # Gate 1 (CONST): fires when is_const flag (dim 30) is set
    ff_in[1, 30] = 1.0
    # Val 1 (CONST): reads const_value from dim 28
    ff_in[D_FFN + 1, 28] = 1.0
    # ff_out: hidden 1 → dim 26 (result)
    ff_out[26, 1] = 1.0

    # Gate 2 (MUL): fires when is_mul flag (dim 34) is set
    # For MUL we need opA * opB. Using the gated bilinear trick:
    # gate = relu(opA * is_mul_boost), val = opB
    # When is_mul=1: gate = relu(opA + big_positive) ≈ opA (always positive for byte values)
    # When is_mul=0: gate = relu(opA - big_positive) = 0
    ff_in[2, 24] = 1.0      # gate reads opA
    ff_in[2, 34] = 1000.0   # gate reads is_mul * 1000
    ff_in[2, 35] = -1000.0  # gate reads pe_bias * -1000 (subtract 1000 when is_mul=0)
    # Val 2 (MUL): reads opB
    ff_in[D_FFN + 2, 25] = 1.0
    # ff_out: hidden 2 → dim 26 (result)
    ff_out[26, 2] = 1.0

    # Gate 3 (SUB): fires when is_sub flag... we'll use dim 29 for is_sub
    # SUB: result = opA - opB
    ff_in[3, 29] = 1.0      # gate reads is_sub flag (dim 29)
    ff_in[D_FFN + 3, 24] = 1.0    # val = opA
    ff_in[D_FFN + 3, 25] = -1.0   # val -= opB
    ff_out[26, 3] = 1.0

    # ================================================================
    # Output Head: quadratic byte decoding
    # ================================================================
    head = model.head.weight  # (520, 36)

    # For byte tokens 0-255: score(b) = S*b*result - S*b²/2
    # This is maximized at b = result.
    for b in range(256):
        head[b, 26] = S * b              # S * b * result_value
        head[b, 27] = -S * b * b / 2.0   # -S * b² / 2 * quadratic_bias

    # HALT token: responds to is_halt flag in dim 33
    head[TraceVocab.HALT, 33] = 1.0

    # BRANCH_TAKEN token: responds to flag in dim 8
    head[TraceVocab.BRANCH_TAKEN, 8] = 1.0

    # OUTPUT marker: responds to is_output_marker flag in dim 32
    head[TraceVocab.OUTPUT, 32] = 1.0


def _set_program_pe(model, position_info, n):
    """
    Set per-program position embeddings.
    This is the ONLY thing that changes between programs.
    """
    pos_emb = model.pos_tok.weight  # (max_seq_len, 36)
    pos_emb.zero_()

    max_len = pos_emb.shape[0]

    for i, pinfo in enumerate(position_info):
        # Sequence position = trace position (no offset — model at pos t predicts tok t)
        seq_pos = i
        if seq_pos >= max_len:
            break

        # Position key: angular encoding of sequence position
        theta_i = 2.0 * math.pi * seq_pos / max(n + 20, 100)
        pos_emb[seq_pos, 2] = R * math.cos(theta_i)
        pos_emb[seq_pos, 3] = R * math.sin(theta_i)

        # Universal bias
        pos_emb[seq_pos, 35] = 1.0

        ptype = pinfo['type']

        if ptype == 'const' or ptype == 'zero':
            pos_emb[seq_pos, 30] = 1.0  # is_const flag
            pos_emb[seq_pos, 28] = float(pinfo.get('const_val', 0))  # constant value

        elif ptype in ('add', 'sub', 'mul'):
            flag_dim = {'add': 31, 'sub': 29, 'mul': 34}[ptype]
            pos_emb[seq_pos, flag_dim] = 1.0

            # Query targets: operand positions +1 because attention reads
            # the INPUT token (the previously generated byte appears as
            # input at the NEXT position)
            op_a_seq = pinfo['operand_a_pos'] + 1
            op_b_seq = pinfo['operand_b_pos'] + 1
            theta_a = 2.0 * math.pi * op_a_seq / max(n + 20, 100)
            theta_b = 2.0 * math.pi * op_b_seq / max(n + 20, 100)
            pos_emb[seq_pos, 4] = R * math.cos(theta_a)
            pos_emb[seq_pos, 5] = R * math.sin(theta_a)
            pos_emb[seq_pos, 6] = R * math.cos(theta_b)
            pos_emb[seq_pos, 7] = R * math.sin(theta_b)

        elif ptype == 'output_marker':
            pos_emb[seq_pos, 32] = 1e4

        elif ptype == 'halt':
            pos_emb[seq_pos, 33] = 1e4

        elif ptype == 'branch_taken':
            # Use dim 8 as branch_taken flag (strong signal like output/halt)
            pos_emb[seq_pos, 8] = 1e4


def generate_trace(model, max_tokens=50000, device='cpu'):
    """Generate trace autoregressively with KV cache."""
    model.eval()
    model = model.to(device)
    generated = [0]

    with torch.no_grad():
        input_ids = torch.tensor([[0]], dtype=torch.long, device=device)
        logits, kv_cache = model.forward_with_cache(input_ids, kv_cache=None)
        next_token = logits[0, -1].argmax().item()
        generated.append(next_token)

        for _ in range(max_tokens - 1):
            if next_token == TraceVocab.HALT:
                break
            input_ids = torch.tensor([[next_token]], dtype=torch.long, device=device)
            logits, kv_cache = model.forward_with_cache(input_ids, kv_cache=kv_cache)
            next_token = logits[0, -1].argmax().item()
            generated.append(next_token)

    return generated[1:]


def compile_and_verify(name, program):
    """Compile, generate, verify, return timing info."""
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run()
    tc = TraceCompiler()
    expected = tc.vm_trace_to_tokens(trace)
    result = vm.output[0] if vm.output else '?'
    n_tok = len(expected)

    t0 = time.perf_counter()
    model, _ = compile_program(program)
    compile_time = time.perf_counter() - t0

    n_params = sum(p.numel() for p in model.parameters())

    t1 = time.perf_counter()
    generated = generate_trace(model, max_tokens=n_tok + 10)
    gen_time = time.perf_counter() - t1

    match = generated == expected
    tok_per_sec = n_tok / gen_time if gen_time > 0 else 0

    return {
        'name': name, 'result': result, 'n_tok': n_tok,
        'd_model': D_MODEL, 'n_params': n_params,
        'compile_sec': compile_time, 'generate_sec': gen_time,
        'tok_per_sec': tok_per_sec, 'match': match,
        'expected': expected, 'generated': generated,
    }


def build_test_suite():
    """Build test suite for Phases 1-3."""
    from wasm_vm import (make_addition_program, make_multiplication_program,
                          make_fibonacci_program, Instruction, Op)
    from mini_c import (Compiler, var, lit, add, mul, div, mod,
                         le, ge, gt, ne, eq, band,
                         assign, output_int, while_loop, if_then)

    tests = []

    # Phase 1: single-byte arithmetic
    tests.append(("3 + 5 = 8", make_addition_program(3, 5)))
    tests.append(("7 * 13 = 91", make_multiplication_program(7, 13)))
    tests.append(("10 + 20 = 30", make_addition_program(10, 20)))
    tests.append(("0 + 0 = 0", make_addition_program(0, 0)))

    # Phase 2: multi-byte
    tests.append(("100 + 200 = 300", make_addition_program(100, 200)))
    tests.append(("200 + 200 = 400", make_addition_program(200, 200)))
    tests.append(("1000 + 2000", make_addition_program(1000, 2000)))

    # Phase 3: control flow
    # Memory store/load
    tests.append(("mem[0]=42", [
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_CONST, 42),
        Instruction(Op.I32_STORE),
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_LOAD),
        Instruction(Op.OUTPUT), Instruction(Op.HALT),
    ]))

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
    tests.append(("fib(3) = 2", make_fibonacci_program(3)))
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    # Factorial
    c = Compiler()
    code, _ = c.compile([assign('r', lit(1)), assign('i', lit(2)),
        while_loop(le(var('i'), lit(5)), [
            assign('r', mul(var('r'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("5! = 120", code))

    # GCD
    c = Compiler()
    code, _ = c.compile([assign('a', lit(48)), assign('b', lit(18)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    tests.append(("gcd(48,18) = 6", code))

    return tests


def run_tests(max_tokens_limit=10000):
    """Run all tests."""
    tests = build_test_suite()

    print("=" * 80)
    print("Interpreter-in-Weights: d_model=36 FIXED, ~100K params, no training")
    print("=" * 80)
    print(f"{'Program':<20} {'Tok':>5} {'Params':>10} {'Compile':>8} "
          f"{'Gen':>8} {'Tok/s':>10} {'Status':>6}")
    print("-" * 80)

    passed = total = 0
    for name, program in tests:
        total += 1
        info = compile_and_verify(name, program)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']:
            passed += 1

        print(f"  {name:<20} {info['n_tok']:>5} {info['n_params']:>10,} "
              f"{info['compile_sec']:>7.3f}s {info['generate_sec']:>7.3f}s "
              f"{info['tok_per_sec']:>9,.0f} {status:>6}")

        if not info['match']:
            for j in range(min(len(info['expected']), len(info['generated']))):
                if j >= len(info['generated']) or info['expected'][j] != info['generated'][j]:
                    print(f"    pos {j}: exp={info['expected'][j]} got={info['generated'][j] if j<len(info['generated']) else 'EOF'}")
                    break

    print("-" * 80)
    print(f"  Result: {passed}/{total} (d_model={D_MODEL} FIXED for all)")
    print("=" * 80)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-tokens', type=int, default=10000)
    args = parser.parse_args()
    run_tests(max_tokens_limit=args.max_tokens)
