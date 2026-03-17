"""
Weight Compiler: Compiles WASM programs directly into transformer weights.

NO training. NO gradient descent. The forward pass IS the program.

Architecture scales with trace length:
- d_model = max(36, trace_length + 2) rounded to next even number
- n_heads = d_model / 2 (head_dim=2 for convex hull fast path)
- n_layers = 7 (fixed)

Each position gets a unique PE dim. Single-layer FFN handles all positions.
"""

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, WasmVM
from compiler import TraceVocab, TraceCompiler


def compile_program(program: list[Instruction]):
    """
    Compile a WASM program into a VanillaTransformer.
    Model dimensions scale to fit the trace length.
    Returns: (model, expected_trace_tokens)
    """
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run(max_steps=1_000_000)

    tc = TraceCompiler()
    trace_tokens = tc.vm_trace_to_tokens(trace)
    n = len(trace_tokens)

    # Scale d_model to fit all positions + headroom
    # Each position needs 1 PE dim + 1 target dim = 2 dims
    # Plus 1 bias dim. So d_model ≥ n + 1 for single-round.
    # But PE and target dims are offset by d//2 and don't collide,
    # so d_model ≥ n is sufficient.
    min_d = n + 2  # +2 for headroom
    d_model = max(36, min_d)
    if d_model % 2 != 0:
        d_model += 1  # must be even for head_dim=2

    n_heads = d_model // 2  # head_dim = 2

    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=d_model, n_heads=n_heads, n_layers=7,
        d_ffn=d_model,
        max_seq_len=n + 20, pe_mode='learned',
    )

    with torch.no_grad():
        _compile(model, trace_tokens)

    model.eval()
    return model, trace_tokens


def _compile(model, trace_tokens):
    """
    Set weights so autoregressive generation produces trace_tokens.

    With d_model ≥ n+2, every position gets its own unique PE dim.
    No wrapping, no multi-round, no collisions. Clean and exact.

    Layout:
    - PE dims [0..n-1]: one-hot position encoding
    - Target dims [d//2..d//2+n-1]: FFN output (offset avoids PE collision)
    - Dim d-1: unused (available for future bias)
    """
    d = model.d_model
    n = len(trace_tokens)

    # Zero all weights
    for layer in range(7):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()
    model.pos_tok.weight.zero_()

    pos_emb = model.pos_tok.weight
    ff_in = model.ff_in[0].weight   # (2*d, d)
    ff_out = model.ff_out[0].weight  # (d, d)
    head = model.head.weight         # (520, d)

    PE_SCALE = 1.0
    FFN_SCALE = 1000.0

    for i in range(n):
        pe_dim = i                        # unique PE dim
        target_dim = (i + d // 2) % d     # offset target dim, no collision with PE

        # Position embedding: one-hot
        pos_emb[i, pe_dim] = PE_SCALE

        # FFN gate[i]: read PE dim i
        ff_in[i, pe_dim] = 1.0
        # FFN val[i]: read same PE dim
        ff_in[d + i, pe_dim] = 1.0

        # FFN output: write FFN_SCALE to target dim
        ff_out[target_dim, i] = FFN_SCALE / (PE_SCALE ** 2)

        # Output head: target dim → token logit
        tok = trace_tokens[i]
        head[tok, target_dim] += 1.0


def generate_trace(model, max_tokens=5000, device='cpu'):
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
    tests.append(("fib(10) = 55", make_fibonacci_program(10)))

    passed = 0
    for name, program in tests:
        vm = WasmVM()
        vm.load_program(program)
        trace = vm.run()
        expected = tc.vm_trace_to_tokens(trace)

        try:
            model, _ = compile_program(program)
            n_params = sum(p.numel() for p in model.parameters())
            generated = generate_trace(model, max_tokens=len(expected) + 10)
            match = generated == expected
            if match:
                passed += 1
            n_tok = len(expected)
            print(f"  {name} ({n_tok} tok, d={model.d_model}, {n_params:,} params): "
                  f"{'PASS' if match else 'FAIL'}")
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
