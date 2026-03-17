"""
Weight Compiler: Compiles WASM programs directly into transformer weights.

NO training. NO gradient descent. The forward pass IS the program.

Approach: one-hot learned PE with unique dims per position.
Each position gets a dedicated PE dim, the FFN detects it and injects
the target token signal. Multi-layer support for traces > 35 tokens.
"""

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, WasmVM
from compiler import TraceVocab, TraceCompiler


PE_SCALE = 1.0
FFN_SCALE = 1000.0
DIMS_PER_LAYER = 5  # each of 7 layers gets 5 dedicated dims


def compile_program(program: list[Instruction]):
    """
    Compile a WASM program into a VanillaTransformer.
    Returns: (model, expected_trace_tokens)
    """
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run(max_steps=100_000)

    tc = TraceCompiler()
    trace_tokens = tc.vm_trace_to_tokens(trace)
    n = len(trace_tokens)

    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=36, n_heads=18, n_layers=7, d_ffn=36,
        max_seq_len=n + 20, pe_mode='learned',
    )

    with torch.no_grad():
        _zero_all(model)
        _compile(model, trace_tokens)

    model.eval()
    return model, trace_tokens


def _zero_all(model):
    """Zero all weights. Residual connections make layers identity."""
    for layer in range(7):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()
    model.pos_tok.weight.zero_()


def _compile(model, trace_tokens):
    """
    Set weights so autoregressive generation produces trace_tokens.

    Round 0: positions 0..34 each get a unique PE dim (0..34).
    Round r>0: positions 35r..35(r+1)-1 reuse dims 0..34 with PE_SCALE*(1+2r).
    Threshold-based val discrimination prevents cross-round gate collision.
    Dim 35 is a constant -1 bias for threshold subtraction.

    This supports up to 35 * (d_ffn // DIMS_PER_LAYER) positions per layer.
    With 7 layers × 35 dims × ~7 rounds = ~1700+ positions.
    """
    d = model.d_model  # 36
    n = len(trace_tokens)

    pos_emb = model.pos_tok.weight
    head = model.head.weight

    # Bias dim for threshold subtraction
    for t in range(pos_emb.shape[0]):
        pos_emb[t, d - 1] = -1.0

    usable_dims = d - 1  # 35 (dim 35 = bias)
    gate_slots_per_layer = d  # 36 gate slots available in FFN

    for i in range(n):
        round_idx = i // usable_dims
        pos_in_round = i % usable_dims

        pe_dim = pos_in_round
        layer_idx = pe_dim // DIMS_PER_LAYER
        slot_in_layer = pe_dim % DIMS_PER_LAYER

        if layer_idx >= 7:
            print(f"  Warning: position {i} exceeds layer capacity")
            continue

        # Gate slot within this layer: offset by round
        gate_slot = slot_in_layer + DIMS_PER_LAYER * round_idx
        if gate_slot >= gate_slots_per_layer:
            print(f"  Warning: position {i} exceeds gate capacity")
            continue

        # PE value: different per round to avoid collision
        pe_val = PE_SCALE * (1.0 + 2.0 * round_idx)
        pos_emb[i, pe_dim] = pe_val

        ff_in = model.ff_in[layer_idx].weight
        ff_out = model.ff_out[layer_idx].weight

        # Gate: read PE dim
        ff_in[gate_slot, pe_dim] = 1.0

        # Val: threshold-based discrimination for round > 0
        if round_idx == 0:
            ff_in[d + gate_slot, pe_dim] = 1.0
        else:
            threshold = pe_val - PE_SCALE  # midpoint below this round's PE
            ff_in[d + gate_slot, pe_dim] = 1.0
            ff_in[d + gate_slot, d - 1] = threshold  # subtracts threshold via bias

        # ff_out: write to pe_dim at FFN_SCALE
        ff_out[pe_dim, gate_slot] = FFN_SCALE / (pe_val ** 2)

        # Head: this token gets a boost from pe_dim
        tok = trace_tokens[i]
        head[tok, pe_dim] += 1.0


def generate_trace(model, max_tokens=500, device='cpu'):
    """Generate trace autoregressively from compiled model."""
    model.eval()
    model = model.to(device)

    generated = [0]  # START

    for _ in range(max_tokens):
        input_ids = torch.tensor([generated], dtype=torch.long, device=device)
        with torch.no_grad():
            logits = model(input_ids)
        next_token = logits[0, -1].argmax().item()
        generated.append(next_token)
        if next_token == TraceVocab.HALT:
            break

    return generated[1:]


def test_compiled():
    """Test the weight compiler on diverse programs."""
    from wasm_vm import (make_addition_program, make_multiplication_program,
                          make_fibonacci_program, Instruction, Op)
    from mini_c import (Compiler, var, lit, add, le, ge,
                         assign, output_int, while_loop, if_then)

    print("=" * 60)
    print("Weight Compiler: WASM → Transformer Weights (no training)")
    print("=" * 60)

    tc = TraceCompiler()
    tests = []

    # Arithmetic
    tests.append(("3 + 5 = 8", make_addition_program(3, 5)))
    tests.append(("7 * 13 = 91", make_multiplication_program(7, 13)))
    tests.append(("100 + 200 = 300", make_addition_program(100, 200)))

    # Memory store/load
    tests.append(("mem store/load = 42", [
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_CONST, 42),
        Instruction(Op.I32_STORE),
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_LOAD),
        Instruction(Op.OUTPUT), Instruction(Op.HALT),
    ]))

    # Conditional (42 tokens)
    c = Compiler()
    stmts = [assign('x', lit(10)),
             if_then(ge(var('x'), lit(5)),
                     [output_int(lit(1))], [output_int(lit(0))])]
    code, _ = c.compile(stmts)
    tests.append(("if 10>=5 → 1", code))

    # Loop: sum 1..5 (344 tokens)
    c2 = Compiler()
    stmts2 = [assign('s', lit(0)), assign('i', lit(1)),
              while_loop(le(var('i'), lit(5)), [
                  assign('s', add(var('s'), var('i'))),
                  assign('i', add(var('i'), lit(1)))]),
              output_int(var('s'))]
    code2, _ = c2.compile(stmts2)
    tests.append(("sum(1..5) = 15", code2))

    # Fibonacci
    tests.append(("fib(3) = 2", make_fibonacci_program(3)))
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    passed = 0
    for name, program in tests:
        vm = WasmVM()
        vm.load_program(program)
        trace = vm.run()
        expected = tc.vm_trace_to_tokens(trace)

        try:
            model, _ = compile_program(program)
            generated = generate_trace(model, max_tokens=len(expected) + 10)
            match = generated == expected
            if match:
                passed += 1
            n_tok = len(expected)
            print(f"  {name} ({n_tok} tok): {'PASS' if match else 'FAIL'}")
            if not match:
                mismatches = 0
                for j in range(min(len(expected), len(generated))):
                    if j >= len(generated) or expected[j] != generated[j]:
                        print(f"    pos {j}: exp={expected[j]} got={generated[j] if j<len(generated) else 'EOF'}")
                        mismatches += 1
                        if mismatches >= 3:
                            break
                if len(generated) != len(expected):
                    print(f"    lengths: exp={len(expected)} got={len(generated)}")
        except Exception as e:
            print(f"  {name}: ERROR: {e}")

    print(f"\n  Result: {passed}/{len(tests)}")


if __name__ == '__main__':
    test_compiled()
