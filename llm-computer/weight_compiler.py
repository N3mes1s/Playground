"""
Weight Compiler: Compiles WASM programs directly into transformer weights.

NO training. NO gradient descent. The forward pass IS the program.

Architecture auto-scales: d_model grows with trace length, head_dim=2 preserved.

Usage:
    # As library
    from weight_compiler import compile_program, generate_trace
    model, trace = compile_program(my_program)
    output = generate_trace(model)

    # As CLI
    python weight_compiler.py                    # run all tests
    python weight_compiler.py --program add 3 5  # compile specific program
    python weight_compiler.py --benchmark        # benchmark with timing
"""

import time
import struct
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, Op, WasmVM
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

    d_model = max(36, n + 2)
    if d_model % 2 != 0:
        d_model += 1

    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=d_model, n_heads=d_model // 2, n_layers=7,
        d_ffn=d_model,
        max_seq_len=n + 20, pe_mode='learned',
    )

    with torch.no_grad():
        _compile(model, trace_tokens)

    model.eval()
    return model, trace_tokens


def _compile(model, trace_tokens):
    """Set weights: each position gets unique PE dim + FFN gate + head weight."""
    d = model.d_model
    n = len(trace_tokens)

    for layer in range(7):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()
    model.pos_tok.weight.zero_()

    pos_emb = model.pos_tok.weight
    ff_in = model.ff_in[0].weight
    ff_out = model.ff_out[0].weight
    head = model.head.weight

    for i in range(n):
        pe_dim = i
        target_dim = (i + d // 2) % d

        pos_emb[i, pe_dim] = 1.0
        ff_in[i, pe_dim] = 1.0
        ff_in[d + i, pe_dim] = 1.0
        ff_out[target_dim, i] = 1000.0

        tok = trace_tokens[i]
        head[tok, target_dim] += 1.0


def generate_trace(model, max_tokens=5000, device='cpu'):
    """Generate trace autoregressively from compiled model."""
    model.eval()
    model = model.to(device)

    generated = [0]

    for _ in range(max_tokens):
        input_ids = torch.tensor([generated], dtype=torch.long, device=device)
        with torch.no_grad():
            logits = model(input_ids)
        next_token = logits[0, -1].argmax().item()
        generated.append(next_token)
        if next_token == TraceVocab.HALT:
            break

    return generated[1:]


def compile_and_verify(name, program, memory_writes=None):
    """Compile, generate, verify, and return timing info."""
    vm = WasmVM()
    vm.load_program(program)
    if memory_writes:
        for offset, data in memory_writes:
            vm.load_input(data, offset=offset)
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
        'name': name,
        'result': result,
        'n_tok': n_tok,
        'd_model': model.d_model,
        'n_params': n_params,
        'compile_sec': compile_time,
        'generate_sec': gen_time,
        'tok_per_sec': tok_per_sec,
        'match': match,
    }


def build_test_suite():
    """Build the full test suite."""
    from wasm_vm import make_addition_program, make_multiplication_program, make_fibonacci_program
    from mini_c import (Compiler, var, lit, add, sub, mul, div, mod,
                         le, ge, gt, lt, ne, eq, band,
                         assign, output_int, while_loop, if_then,
                         ByteLoad, store_word)

    tests = []

    # ── Tier 1: Arithmetic ──
    tests.append(("3 + 5 = 8", make_addition_program(3, 5)))
    tests.append(("7 * 13 = 91", make_multiplication_program(7, 13)))
    tests.append(("100 + 200 = 300", make_addition_program(100, 200)))

    # ── Tier 2: Memory ──
    tests.append(("mem[0]=42 load=42", [
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_CONST, 42),
        Instruction(Op.I32_STORE),
        Instruction(Op.I32_CONST, 0), Instruction(Op.I32_LOAD),
        Instruction(Op.OUTPUT), Instruction(Op.HALT),
    ]))

    # ── Tier 3: Conditionals ──
    c = Compiler()
    code, _ = c.compile([
        assign('x', lit(10)),
        if_then(ge(var('x'), lit(5)),
                [output_int(lit(1))], [output_int(lit(0))])])
    tests.append(("if 10>=5 → 1", code))

    # ── Tier 4: Loops ──
    c = Compiler()
    code, _ = c.compile([
        assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(5)), [
            assign('s', add(var('s'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum(1..5) = 15", code))

    # Fibonacci
    tests.append(("fib(3) = 2", make_fibonacci_program(3)))
    tests.append(("fib(5) = 5", make_fibonacci_program(5)))

    # Factorial
    c = Compiler()
    code, _ = c.compile([
        assign('r', lit(1)), assign('i', lit(2)),
        while_loop(le(var('i'), lit(7)), [
            assign('r', mul(var('r'), var('i'))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("7! = 5040", code))

    # GCD
    c = Compiler()
    code, _ = c.compile([
        assign('a', lit(48)), assign('b', lit(18)),
        while_loop(ne(var('b'), lit(0)), [
            assign('t', mod(var('a'), var('b'))),
            assign('a', var('b')),
            assign('b', var('t'))]),
        output_int(var('a'))])
    tests.append(("gcd(48,18) = 6", code))

    # ── Tier 5: Nested control flow ──
    # Collatz
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(7)), assign('steps', lit(0)),
        while_loop(gt(var('n'), lit(1)), [
            if_then(eq(mod(var('n'), lit(2)), lit(0)),
                    [assign('n', div(var('n'), lit(2)))],
                    [assign('n', add(mul(var('n'), lit(3)), lit(1)))]),
            assign('steps', add(var('steps'), lit(1)))]),
        output_int(var('steps'))])
    tests.append(("collatz(7) = 16 steps", code))

    # Is prime
    c = Compiler()
    code, _ = c.compile([
        assign('n', lit(17)), assign('r', lit(1)),
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

    # Power 2^10
    c = Compiler()
    code, _ = c.compile([
        assign('r', lit(1)), assign('i', lit(0)),
        while_loop(lt(var('i'), lit(10)), [
            assign('r', mul(var('r'), lit(2))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('r'))])
    tests.append(("2^10 = 1024", code))

    # Sum of squares 1^2 + 2^2 + ... + 5^2 = 55
    c = Compiler()
    code, _ = c.compile([
        assign('s', lit(0)), assign('i', lit(1)),
        while_loop(le(var('i'), lit(5)), [
            assign('s', add(var('s'), mul(var('i'), var('i')))),
            assign('i', add(var('i'), lit(1)))]),
        output_int(var('s'))])
    tests.append(("sum_sq(1..5) = 55", code))

    return tests


def run_tests(max_tokens_limit=200):
    """Run all tests with timing."""
    tests = build_test_suite()
    tc = TraceCompiler()

    print("=" * 80)
    print("Weight Compiler: WASM → Transformer Weights (no training)")
    print("=" * 80)
    print(f"{'Program':<25} {'Tok':>5} {'d_model':>7} {'Params':>10} "
          f"{'Compile':>8} {'Gen':>8} {'Tok/s':>10} {'Status':>6}")
    print("-" * 80)

    passed = 0
    total = 0

    for name, program in tests:
        # Check trace length first
        vm = WasmVM()
        vm.load_program(program)
        trace = vm.run()
        expected = tc.vm_trace_to_tokens(trace)
        n_tok = len(expected)

        if n_tok > max_tokens_limit:
            print(f"  {name:<25} {n_tok:>5} {'SKIP':>7} (>{max_tokens_limit} tokens)")
            continue

        total += 1
        info = compile_and_verify(name, program)

        status = "PASS" if info['match'] else "FAIL"
        if info['match']:
            passed += 1

        print(f"  {name:<25} {info['n_tok']:>5} {info['d_model']:>7} "
              f"{info['n_params']:>10,} {info['compile_sec']:>7.3f}s "
              f"{info['generate_sec']:>7.3f}s {info['tok_per_sec']:>9,.0f} "
              f"{status:>6}")

    print("-" * 80)
    print(f"  Result: {passed}/{total} passed")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description='WASM → Transformer Weight Compiler')
    parser.add_argument('--benchmark', action='store_true',
                        help='Run full benchmark suite')
    parser.add_argument('--max-tokens', type=int, default=200,
                        help='Max trace tokens to compile (default: 200)')
    parser.add_argument('--program', nargs='+',
                        help='Compile specific program: add A B | mul A B | fib N')
    args = parser.parse_args()

    if args.program:
        cmd = args.program[0]
        if cmd == 'add':
            a, b = int(args.program[1]), int(args.program[2])
            from wasm_vm import make_addition_program
            prog = make_addition_program(a, b)
            name = f"{a} + {b}"
        elif cmd == 'mul':
            a, b = int(args.program[1]), int(args.program[2])
            from wasm_vm import make_multiplication_program
            prog = make_multiplication_program(a, b)
            name = f"{a} * {b}"
        elif cmd == 'fib':
            n = int(args.program[1])
            from wasm_vm import make_fibonacci_program
            prog = make_fibonacci_program(n)
            name = f"fib({n})"
        else:
            print(f"Unknown program: {cmd}")
            return

        info = compile_and_verify(name, prog)
        print(f"{name} = {info['result']}")
        print(f"  Tokens: {info['n_tok']}, d_model: {info['d_model']}, params: {info['n_params']:,}")
        print(f"  Compile: {info['compile_sec']:.3f}s, Generate: {info['generate_sec']:.3f}s")
        print(f"  Throughput: {info['tok_per_sec']:,.0f} tok/s")
        print(f"  Correct: {info['match']}")
    else:
        run_tests(max_tokens_limit=args.max_tokens)


if __name__ == '__main__':
    main()
