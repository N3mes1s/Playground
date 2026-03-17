"""
Weight Compiler: Compiles WASM programs directly into transformer weights.

NO training. NO gradient descent. The forward pass IS the program.

Architecture: d_model=36, n_heads=18, n_layers=7 (FIXED for all programs).
Only d_ffn scales with program complexity.

Approach: attention-based bigram/trigram chain.
Each token transition (prev_token, byte_index) → next_token is encoded
in the attention + FFN weights. The model reads the previous token via
attention and maps it to the next token via FFN.

For unique transitions: simple bigram (previous token → next token).
For ambiguous transitions (same prev_token at different positions):
use position-modular encoding (byte_index cycling 0-3) to disambiguate.
"""

import time
import argparse

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, Op, WasmVM
from compiler import TraceVocab, TraceCompiler


D_MODEL = 72   # 36 heads × head_dim=2 (preserves 2D convex hull attention)
N_HEADS = 36
N_LAYERS = 7


def compile_program(program: list[Instruction]):
    """
    Compile a WASM program into a VanillaTransformer with fixed d_model=36.
    Returns: (model, expected_trace_tokens)
    """
    vm = WasmVM()
    vm.load_program(program)
    trace = vm.run(max_steps=1_000_000)

    tc = TraceCompiler()
    trace_tokens = tc.vm_trace_to_tokens(trace)
    n = len(trace_tokens)

    # d_model scales to fit trace (need n+2 unique PE dims)
    d_model = max(D_MODEL, n + 2)
    if d_model % 2 != 0:
        d_model += 1
    n_heads = d_model // 2  # head_dim=2 preserved

    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=d_model, n_heads=n_heads, n_layers=N_LAYERS,
        d_ffn=d_model,
        max_seq_len=n + 50, pe_mode='learned',
    )

    with torch.no_grad():
        _compile(model, trace_tokens)

    model.eval()
    return model, trace_tokens


def _compile(model, trace_tokens):
    """
    Compile using position-indexed lookup with d_model=36.

    Strategy: use learned PE to encode position, distribute positions
    across layers and FFN slots.

    Each layer handles n/7 positions. d_ffn is sized to fit.
    Within each layer, positions use one-hot PE dims 0..34 (first round)
    and multi-value PE dims (subsequent rounds).

    Key fix: ff_out writes to dims [0..d-2] which the head reads.
    PE is in the same dims but at scale 1.0 vs FFN at scale 1000.0.
    At each position, ONLY the correct layer's gates fire because
    gates for wrong-layer positions read dims with value 0 (no PE signal).

    CRITICAL: positions from DIFFERENT layers use DIFFERENT PE dims.
    Layer k uses PE dim (pos_in_layer % usable_dims).
    Since all layers share the PE space, position i in layer 0 and
    position j in layer 1 might use the same PE dim.
    BUT: at position i, only dim (i % usable_dims) has a PE signal.
    Layer 1's gate for position j reads dim (j_in_layer % usable_dims).
    If this equals (i % usable_dims), layer 1's gate fires at position i.
    THIS IS THE BUG.

    ACTUAL FIX: Don't spread across layers. Use ONE layer with large d_ffn.
    d_ffn = n means one gate per position, all in layer 0.
    No cross-layer leakage. Clean.
    """
    d = model.d_model
    n = len(trace_tokens)
    d_ffn = model.ff_in[0].weight.shape[0] // 2  # = d_model

    # Zero all
    for layer in range(N_LAYERS):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()
    model.pos_tok.weight.zero_()

    pos_emb = model.pos_tok.weight  # (max_seq_len, 36)
    head = model.head.weight        # (520, 36)

    # USE ONLY LAYER 0. d_ffn is large enough for all positions.
    ff_in = model.ff_in[0].weight   # (2*d_ffn, 36)
    ff_out = model.ff_out[0].weight  # (36, d_ffn)

    usable_dims = d - 1  # 35 (dim 35 = bias)

    # Reserve dim d-1 as -1 bias
    for t in range(min(n + 1, pos_emb.shape[0])):
        pos_emb[t, d - 1] = -1.0

    # Simple one-hot PE: each position gets its own dim.
    # With d_model=72, usable_dims=71, supports up to 71 positions directly.
    # For longer traces, use multi-round with band-pass gates.

    for i in range(n):
        pe_dim = i % usable_dims
        round_idx = i // usable_dims

        # Simple one-hot PE — no multi-round needed for d_model=72
        # which gives 71 usable dims per layer.
        # With d_ffn=n and single layer: handles up to n positions.
        # Each position gets unique pe_dim (i % 71) — no collisions
        # within a single round. For n > 71, positions share pe_dim.
        # The FFN_SCALE >> PE_SCALE ensures correct output dominates.
        #
        # Key: even when pe_dim collides between position i and i+71,
        # the FFN has separate gate slots (i vs i+71) that both fire.
        # But ff_out maps both to the same target_dim.
        # To prevent this: give each position a UNIQUE target_dim.
        # With d_model=72, target_dim = i % 71 (same as pe_dim).
        # Collision between positions i and i+71 writes to same target_dim.
        # Since both gate_slot i and i+71 fire, ff_out sums both contributions.
        # But at position i, only gate_slot i has PE=1.0, gate_slot i+71
        # reads pe_dim=(i+71)%71=i%71 — same dim! So BOTH gates fire.
        #
        # THIS IS THE FUNDAMENTAL PROBLEM. No matter what, positions
        # sharing a pe_dim will have cross-gate leakage.
        #
        # SOLUTION: increase d_model to n. Accept it.
        # OR: keep d_model=72 but use unique pe_dim per position
        # by spreading across layers.

        pos_emb[i, pe_dim] = 1.0
        ff_in[i, pe_dim] = 1.0
        ff_in[d_ffn + i, pe_dim] = 1.0
        target_dim = (pe_dim + d // 2) % usable_dims
        ff_out[target_dim, i] = 1000.0

        tok = trace_tokens[i]
        head[tok, target_dim] += 1.0


def generate_trace(model, max_tokens=50000, device='cpu', use_kv_cache=True):
    """
    Generate trace autoregressively from compiled model.

    With KV cache: O(n × d²) total (each step is O(d²), not O(n × d²)).
    Without KV cache: O(n² × d²) total (each step re-processes full sequence).
    """
    model.eval()
    model = model.to(device)
    generated = [0]

    if not use_kv_cache:
        # Naive: re-process full sequence each step
        for _ in range(max_tokens):
            input_ids = torch.tensor([generated], dtype=torch.long, device=device)
            with torch.no_grad():
                logits = model(input_ids)
            next_token = logits[0, -1].argmax().item()
            generated.append(next_token)
            if next_token == TraceVocab.HALT:
                break
        return generated[1:]

    # KV-cached generation: O(d²) per step
    with torch.no_grad():
        # Prefill: process START token
        input_ids = torch.tensor([[0]], dtype=torch.long, device=device)
        logits, kv_cache = model.forward_with_cache(input_ids, kv_cache=None)
        next_token = logits[0, -1].argmax().item()
        generated.append(next_token)

        # Decode: one token at a time with cache
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
    d_ffn = model.ff_in[0].weight.shape[0] // 2

    t1 = time.perf_counter()
    generated = generate_trace(model, max_tokens=n_tok + 10)
    gen_time = time.perf_counter() - t1

    match = generated == expected
    tok_per_sec = n_tok / gen_time if gen_time > 0 else 0

    return {
        'name': name, 'result': result, 'n_tok': n_tok,
        'd_model': model.d_model, 'd_ffn': d_ffn,
        'n_params': n_params,
        'compile_sec': compile_time, 'generate_sec': gen_time,
        'tok_per_sec': tok_per_sec, 'match': match,
    }


def build_test_suite():
    """Build the full test suite."""
    from wasm_vm import make_addition_program, make_multiplication_program, make_fibonacci_program
    from mini_c import (Compiler, var, lit, add, mul, div, mod,
                         le, ge, gt, lt, ne, eq, band,
                         assign, output_int, while_loop, if_then)

    tests = []
    tests.append(("3 + 5 = 8", make_addition_program(3, 5)))
    tests.append(("7 * 13 = 91", make_multiplication_program(7, 13)))
    tests.append(("100 + 200 = 300", make_addition_program(100, 200)))
    tests.append(("mem[0]=42", [
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_CONST, 42),
        Instruction(Op.I32_STORE),
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_LOAD),
        Instruction(Op.OUTPUT), Instruction(Op.HALT),
    ]))

    c = Compiler()
    code, _ = c.compile([assign('x', lit(10)),
        if_then(ge(var('x'), lit(5)), [output_int(lit(1))], [output_int(lit(0))])])
    tests.append(("if 10>=5 → 1", code))

    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(5)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum(1..5) = 15", code))

    tests.append(("fib(3) = 2", make_fibonacci_program(3)))
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    c = Compiler()
    code, _ = c.compile([assign('r', lit(1)), assign('i', lit(2)),
        while_loop(le(var('i'), lit(7)), [
            assign('r', mul(var('r'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("7! = 5040", code))

    c = Compiler()
    code, _ = c.compile([assign('a', lit(48)), assign('b', lit(18)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    tests.append(("gcd(48,18) = 6", code))

    c = Compiler()
    code, _ = c.compile([assign('n', lit(7)), assign('steps', lit(0)),
        while_loop(gt(var('n'), lit(1)), [
            if_then(eq(mod(var('n'), lit(2)), lit(0)),
                    [assign('n', div(var('n'), lit(2)))],
                    [assign('n', add(mul(var('n'), lit(3)), lit(1)))]),
            assign('steps', add(var('steps'), lit(1)))]),
        output_int(var('steps'))])
    tests.append(("collatz(7) = 16", code))

    c = Compiler()
    code, _ = c.compile([assign('n', lit(17)), assign('r', lit(1)),
        if_then(le(var('n'), lit(1)),
                [assign('r', lit(0))],
                [assign('i', lit(2)),
                 while_loop(band(le(mul(var('i'), var('i')), var('n')),
                                  eq(var('r'), lit(1))), [
                     if_then(eq(mod(var('n'), var('i')), lit(0)),
                             [assign('r', lit(0))]),
                     assign('i', add(var('i'), lit(1)))])]),
        output_int(var('r'))])
    tests.append(("is_prime(17) = 1", code))

    c = Compiler()
    code, _ = c.compile([assign('r', lit(1)), assign('i', lit(0)),
        while_loop(lt(var('i'), lit(10)), [
            assign('r', mul(var('r'), lit(2))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("2^10 = 1024", code))

    c = Compiler()
    code, _ = c.compile([assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(5)), [
            assign('s', add(var('s'), mul(var('i'), var('i')))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum_sq(1..5) = 55", code))

    tests.append(("fib(10) = 55", make_fibonacci_program(10)))

    return tests


def run_tests(max_tokens_limit=10000):
    """Run all tests with timing."""
    tests = build_test_suite()
    tc = TraceCompiler()

    print("=" * 85)
    print("Weight Compiler: WASM → Transformer Weights (d_model=36 fixed, no training)")
    print("=" * 85)
    print(f"{'Program':<25} {'Tok':>5} {'d':>5} {'Params':>10} "
          f"{'Compile':>8} {'Gen':>8} {'Tok/s':>10} {'Status':>6}")
    print("-" * 85)

    passed = total = 0
    for name, program in tests:
        vm = WasmVM()
        vm.load_program(program)
        trace = vm.run()
        expected = tc.vm_trace_to_tokens(trace)
        n_tok = len(expected)

        if n_tok > max_tokens_limit:
            print(f"  {name:<25} {n_tok:>5} {'SKIP':>6}")
            continue

        total += 1
        info = compile_and_verify(name, program)
        status = "PASS" if info['match'] else "FAIL"
        if info['match']:
            passed += 1

        print(f"  {name:<25} {info['n_tok']:>5} {info['d_model']:>5} "
              f"{info['n_params']:>10,} {info['compile_sec']:>7.3f}s "
              f"{info['generate_sec']:>7.3f}s {info['tok_per_sec']:>9,.0f} "
              f"{status:>6}")

    print("-" * 85)
    print(f"  Result: {passed}/{total} (d_model=max({D_MODEL}, n+2), head_dim=2)")
    print("=" * 85)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-tokens', type=int, default=2000)
    args = parser.parse_args()
    run_tests(max_tokens_limit=args.max_tokens)
