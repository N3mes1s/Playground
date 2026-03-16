"""
Training Data Generator for the Compute Model.

Based on research findings (Zaremba 2014, Sun 2025, Armengol-Estape 2025):

1. Curriculum learning: "combined" strategy — 50% progressive difficulty +
   50% random mix from all difficulty levels seen so far.
2. Short traces first: <50 steps gives reliable high accuracy with small models.
3. Distribution: 40% arithmetic, 25% conditionals, 20% loops, 10% nested, 5% complex.
4. Within each category: 30% minimal (1-5 steps), 40% medium (5-30 steps),
   20% challenging (30-100 steps), 10% hard (100+ steps).
5. Edge cases: zeros, negatives, boundaries, empty inputs.
"""

import random
import struct
from typing import Optional

from wasm_vm import WasmVM, Instruction, Op, make_addition_program, \
    make_multiplication_program, make_fibonacci_program
from compiler import TraceCompiler, TraceVocab
from mini_c import (
    Compiler, var, lit, add, sub, mul, div, mod,
    eq, ne, lt, gt, le, ge, band, bor,
    byte_at, assign, output_int, output_char,
    store_byte, store_word, if_then, while_loop, for_loop,
    ByteLoad, IntLit, BinOp, Var,
)


class TrainingDataGenerator:
    """
    Generates training pairs for the compute model.

    Each sample is (program_tokens, trace_tokens) where:
    - program_tokens: the WASM program encoded as token sequence
    - trace_tokens: the execution trace the model should produce
    """

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.vm = WasmVM()
        self.trace_compiler = TraceCompiler()

    def _execute(self, code: list[Instruction], n_locals: int = 16,
                 input_data: Optional[bytes] = None,
                 memory_writes: Optional[list[tuple[int, bytes]]] = None,
                 max_steps: int = 100_000) -> Optional[tuple[list[int], list[int]]]:
        """Execute a program and return (program_tokens, trace_tokens)."""
        self.vm.load_program(code, n_locals=n_locals)
        if input_data:
            self.vm.load_input(input_data, offset=0)
        if memory_writes:
            for offset, data in memory_writes:
                self.vm.load_input(data, offset=offset)

        trace = self.vm.run(max_steps=max_steps)
        if not trace:
            return None

        program_tokens = self.trace_compiler.program_to_tokens(code)
        trace_tokens = self.trace_compiler.vm_trace_to_tokens(trace)

        if not trace_tokens:
            return None

        return program_tokens, trace_tokens

    def _compile_and_execute(self, stmts: list, input_data: Optional[bytes] = None,
                              memory_writes: Optional[list[tuple[int, bytes]]] = None,
                              max_steps: int = 100_000) -> Optional[tuple[list[int], list[int]]]:
        """Compile Mini-C statements and execute."""
        compiler = Compiler()
        code, n_locals = compiler.compile(stmts)
        return self._execute(code, n_locals, input_data, memory_writes, max_steps)

    # ================================================================
    # TIER 1: Straight-line arithmetic (40% of dataset)
    # Minimal traces, 3-10 steps. The foundation.
    # ================================================================

    def gen_single_add(self) -> Optional[tuple[list[int], list[int]]]:
        """a + b with varying digit counts."""
        digits = self.rng.choice([1, 1, 1, 2, 2, 3, 4])
        limit = 10 ** digits
        a = self.rng.randint(-limit, limit)
        b = self.rng.randint(-limit, limit)
        return self._execute(make_addition_program(a, b))

    def gen_single_mul(self) -> Optional[tuple[list[int], list[int]]]:
        """a * b."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        return self._execute(make_multiplication_program(a, b))

    def gen_single_sub(self) -> Optional[tuple[list[int], list[int]]]:
        """a - b."""
        a = self.rng.randint(-1000, 1000)
        b = self.rng.randint(-1000, 1000)
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(Op.I32_SUB),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    def gen_single_div(self) -> Optional[tuple[list[int], list[int]]]:
        """a / b (integer division, avoid div by zero)."""
        a = self.rng.randint(-1000, 1000)
        b = self.rng.choice([-10, -5, -3, -2, -1, 1, 2, 3, 5, 7, 10, 13, 100])
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(Op.I32_DIV_S),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    def gen_single_mod(self) -> Optional[tuple[list[int], list[int]]]:
        """a % b."""
        a = self.rng.randint(0, 1000)
        b = self.rng.choice([2, 3, 5, 7, 10, 13, 100])
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(Op.I32_REM_S),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    def gen_arithmetic_chain(self) -> Optional[tuple[list[int], list[int]]]:
        """Chain of 2-5 arithmetic ops: a op b op c ..."""
        ops = [Op.I32_ADD, Op.I32_SUB, Op.I32_MUL]
        n_ops = self.rng.randint(2, 5)
        code = [Instruction(Op.I32_CONST, self.rng.randint(-50, 50))]
        for _ in range(n_ops):
            code.append(Instruction(Op.I32_CONST, self.rng.randint(-50, 50)))
            code.append(Instruction(self.rng.choice(ops)))
        code.append(Instruction(Op.OUTPUT))
        code.append(Instruction(Op.HALT))
        return self._execute(code)

    def gen_expression(self) -> Optional[tuple[list[int], list[int]]]:
        """Multi-variable expression: x = a, y = b, output x*y + x - y."""
        a = self.rng.randint(-20, 20)
        b = self.rng.randint(-20, 20)
        stmts = [
            assign('x', lit(a)),
            assign('y', lit(b)),
            output_int(add(sub(mul(var('x'), var('y')), var('y')), var('x'))),
        ]
        return self._compile_and_execute(stmts)

    def gen_multi_output(self) -> Optional[tuple[list[int], list[int]]]:
        """Multiple outputs: output a, output b, output a+b."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        stmts = [
            assign('a', lit(a)),
            assign('b', lit(b)),
            output_int(var('a')),
            output_int(var('b')),
            output_int(add(var('a'), var('b'))),
        ]
        return self._compile_and_execute(stmts)

    def gen_edge_arithmetic(self) -> Optional[tuple[list[int], list[int]]]:
        """Edge cases: 0, 1, -1, max/min values, identity operations."""
        edge = self.rng.choice([
            (0, 0), (1, 0), (0, 1), (-1, 1), (1, -1),
            (127, 1), (-128, 1), (255, 0), (1000, 1000),
            (0, -1), (-1, -1), (42, 0),
        ])
        a, b = edge
        op = self.rng.choice([Op.I32_ADD, Op.I32_SUB, Op.I32_MUL])
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(op),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    def gen_bitwise(self) -> Optional[tuple[list[int], list[int]]]:
        """Bitwise operations: and, or, xor, shift."""
        a = self.rng.randint(0, 255)
        b = self.rng.randint(0, 255)
        op = self.rng.choice([Op.I32_AND, Op.I32_OR, Op.I32_XOR])
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(op),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    # ================================================================
    # TIER 2: Conditionals (25% of dataset)
    # 5-15 steps. Teaches branching logic.
    # ================================================================

    def gen_comparison(self) -> Optional[tuple[list[int], list[int]]]:
        """a cmp b → 0 or 1."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        cmp_op = self.rng.choice([Op.I32_EQ, Op.I32_NE, Op.I32_LT_S,
                                   Op.I32_GT_S, Op.I32_LE_S, Op.I32_GE_S])
        code = [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.I32_CONST, b),
            Instruction(cmp_op),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
        return self._execute(code)

    def gen_max_min(self) -> Optional[tuple[list[int], list[int]]]:
        """if (a > b) output a; else output b; (max)."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        if self.rng.random() < 0.5:
            # max
            stmts = [
                assign('a', lit(a)), assign('b', lit(b)),
                if_then(gt(var('a'), var('b')),
                        [output_int(var('a'))], [output_int(var('b'))]),
            ]
        else:
            # min
            stmts = [
                assign('a', lit(a)), assign('b', lit(b)),
                if_then(lt(var('a'), var('b')),
                        [output_int(var('a'))], [output_int(var('b'))]),
            ]
        return self._compile_and_execute(stmts)

    def gen_abs_val(self) -> Optional[tuple[list[int], list[int]]]:
        """Absolute value: if x < 0 then -x else x."""
        x = self.rng.randint(-200, 200)
        stmts = [
            assign('x', lit(x)),
            if_then(lt(var('x'), lit(0)),
                    [output_int(sub(lit(0), var('x')))],
                    [output_int(var('x'))]),
        ]
        return self._compile_and_execute(stmts)

    def gen_clamp(self) -> Optional[tuple[list[int], list[int]]]:
        """Clamp x to [lo, hi]."""
        x = self.rng.randint(-200, 200)
        lo, hi = sorted(self.rng.sample(range(-100, 100), 2))
        stmts = [
            assign('x', lit(x)),
            if_then(lt(var('x'), lit(lo)),
                    [assign('x', lit(lo))]),
            if_then(gt(var('x'), lit(hi)),
                    [assign('x', lit(hi))]),
            output_int(var('x')),
        ]
        return self._compile_and_execute(stmts)

    def gen_sign(self) -> Optional[tuple[list[int], list[int]]]:
        """Sign function: -1, 0, or 1."""
        x = self.rng.randint(-100, 100)
        stmts = [
            assign('x', lit(x)),
            if_then(lt(var('x'), lit(0)),
                    [output_int(lit(-1))],
                    [if_then(gt(var('x'), lit(0)),
                             [output_int(lit(1))],
                             [output_int(lit(0))])]),
        ]
        return self._compile_and_execute(stmts)

    def gen_is_even_odd(self) -> Optional[tuple[list[int], list[int]]]:
        """Output 1 if even, 0 if odd."""
        x = self.rng.randint(-200, 200)
        stmts = [
            assign('x', lit(x)),
            if_then(eq(mod(var('x'), lit(2)), lit(0)),
                    [output_int(lit(1))],
                    [output_int(lit(0))]),
        ]
        return self._compile_and_execute(stmts)

    def gen_multi_branch(self) -> Optional[tuple[list[int], list[int]]]:
        """Chained if-else: classify x into ranges."""
        x = self.rng.randint(-100, 100)
        stmts = [
            assign('x', lit(x)),
            if_then(lt(var('x'), lit(-10)),
                    [output_int(lit(0))],
                    [if_then(lt(var('x'), lit(0)),
                             [output_int(lit(1))],
                             [if_then(lt(var('x'), lit(10)),
                                      [output_int(lit(2))],
                                      [output_int(lit(3))])])]),
        ]
        return self._compile_and_execute(stmts)

    # ================================================================
    # TIER 3: Single loops (20% of dataset)
    # 10-50 steps. Core iteration patterns.
    # ================================================================

    def gen_loop_sum(self) -> Optional[tuple[list[int], list[int]]]:
        """Sum of 1..n."""
        n = self.rng.randint(1, 30)
        stmts = [
            assign('sum', lit(0)),
            assign('i', lit(1)),
            while_loop(le(var('i'), lit(n)), [
                assign('sum', add(var('sum'), var('i'))),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('sum')),
        ]
        return self._compile_and_execute(stmts)

    def gen_factorial(self) -> Optional[tuple[list[int], list[int]]]:
        """n! for small n."""
        n = self.rng.randint(1, 8)
        stmts = [
            assign('r', lit(1)),
            assign('i', lit(2)),
            while_loop(le(var('i'), lit(n)), [
                assign('r', mul(var('r'), var('i'))),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('r')),
        ]
        return self._compile_and_execute(stmts)

    def gen_power(self) -> Optional[tuple[list[int], list[int]]]:
        """base^exp."""
        base = self.rng.randint(2, 5)
        exp = self.rng.randint(1, 6)
        stmts = [
            assign('r', lit(1)),
            assign('i', lit(0)),
            while_loop(lt(var('i'), lit(exp)), [
                assign('r', mul(var('r'), lit(base))),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('r')),
        ]
        return self._compile_and_execute(stmts)

    def gen_countdown(self) -> Optional[tuple[list[int], list[int]]]:
        """Output n, n-1, ..., 1, 0."""
        n = self.rng.randint(3, 10)
        stmts = [
            assign('i', lit(n)),
            while_loop(ge(var('i'), lit(0)), [
                output_int(var('i')),
                assign('i', sub(var('i'), lit(1))),
            ]),
        ]
        return self._compile_and_execute(stmts)

    def gen_fibonacci(self) -> Optional[tuple[list[int], list[int]]]:
        """fib(n)."""
        n = self.rng.randint(0, 20)
        code = make_fibonacci_program(n)
        return self._execute(code, max_steps=500_000)

    def gen_gcd(self) -> Optional[tuple[list[int], list[int]]]:
        """GCD via Euclidean algorithm."""
        a = self.rng.randint(1, 200)
        b = self.rng.randint(1, 200)
        stmts = [
            assign('a', lit(a)), assign('b', lit(b)),
            while_loop(ne(var('b'), lit(0)), [
                assign('t', mod(var('a'), var('b'))),
                assign('a', var('b')),
                assign('b', var('t')),
            ]),
            output_int(var('a')),
        ]
        return self._compile_and_execute(stmts)

    def gen_count_digits(self) -> Optional[tuple[list[int], list[int]]]:
        """Count digits in a number."""
        n = self.rng.randint(1, 100000)
        stmts = [
            assign('n', lit(n)),
            assign('count', lit(0)),
            while_loop(gt(var('n'), lit(0)), [
                assign('n', div(var('n'), lit(10))),
                assign('count', add(var('count'), lit(1))),
            ]),
            output_int(var('count')),
        ]
        return self._compile_and_execute(stmts)

    def gen_sum_digits(self) -> Optional[tuple[list[int], list[int]]]:
        """Sum digits of a number."""
        n = self.rng.randint(1, 9999)
        stmts = [
            assign('n', lit(n)),
            assign('sum', lit(0)),
            while_loop(gt(var('n'), lit(0)), [
                assign('sum', add(var('sum'), mod(var('n'), lit(10)))),
                assign('n', div(var('n'), lit(10))),
            ]),
            output_int(var('sum')),
        ]
        return self._compile_and_execute(stmts)

    def gen_char_count(self) -> Optional[tuple[list[int], list[int]]]:
        """Count characters in a string."""
        length = self.rng.randint(1, 20)
        text = ''.join(self.rng.choices('abcdefghij 12345', k=length))
        stmts = [
            assign('c', lit(0)), assign('i', lit(0)),
            while_loop(ne(byte_at(var('i')), lit(0)), [
                assign('c', add(var('c'), lit(1))),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('c')),
        ]
        return self._compile_and_execute(stmts, input_data=text.encode() + b'\x00')

    def gen_word_count(self) -> Optional[tuple[list[int], list[int]]]:
        """Count words."""
        words = ['the', 'fox', 'dog', 'one', 'hi', 'go', 'up']
        n = self.rng.randint(1, 6)
        text = ' '.join(self.rng.choices(words, k=n))
        stmts = [
            assign('c', lit(0)), assign('w', lit(0)), assign('i', lit(0)),
            while_loop(ne(byte_at(var('i')), lit(0)), [
                assign('ch', byte_at(var('i'))),
                if_then(eq(var('ch'), lit(32)),
                        [if_then(var('w'), [
                            assign('c', add(var('c'), lit(1))),
                            assign('w', lit(0))])],
                        [assign('w', lit(1))]),
                assign('i', add(var('i'), lit(1))),
            ]),
            if_then(var('w'), [assign('c', add(var('c'), lit(1)))]),
            output_int(var('c')),
        ]
        return self._compile_and_execute(stmts, input_data=text.encode() + b'\x00')

    # ================================================================
    # TIER 4: Nested constructs (10% of dataset)
    # 20-100 steps. Loop + conditional, nested loops.
    # ================================================================

    def gen_collatz_steps(self) -> Optional[tuple[list[int], list[int]]]:
        """Count Collatz steps to reach 1."""
        n = self.rng.randint(2, 30)
        stmts = [
            assign('n', lit(n)), assign('steps', lit(0)),
            while_loop(gt(var('n'), lit(1)), [
                if_then(eq(mod(var('n'), lit(2)), lit(0)),
                        [assign('n', div(var('n'), lit(2)))],
                        [assign('n', add(mul(var('n'), lit(3)), lit(1)))]),
                assign('steps', add(var('steps'), lit(1))),
            ]),
            output_int(var('steps')),
        ]
        return self._compile_and_execute(stmts, max_steps=500_000)

    def gen_find_max(self) -> Optional[tuple[list[int], list[int]]]:
        """Find max in an array."""
        n = self.rng.randint(3, 8)
        numbers = [self.rng.randint(-50, 50) for _ in range(n)]
        work = 32768
        stmts = [
            assign('max', ByteLoad(lit(work))),
            assign('i', lit(1)),
            while_loop(lt(var('i'), lit(n)), [
                assign('v', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                if_then(gt(var('v'), var('max')),
                        [assign('max', var('v'))]),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('max')),
        ]
        num_bytes = bytearray()
        for v in numbers:
            num_bytes.extend(struct.pack('<i', v))
        return self._compile_and_execute(stmts, memory_writes=[(work, bytes(num_bytes))])

    def gen_find_min(self) -> Optional[tuple[list[int], list[int]]]:
        """Find min in an array."""
        n = self.rng.randint(3, 8)
        numbers = [self.rng.randint(-50, 50) for _ in range(n)]
        work = 32768
        stmts = [
            assign('min', ByteLoad(lit(work))),
            assign('i', lit(1)),
            while_loop(lt(var('i'), lit(n)), [
                assign('v', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                if_then(lt(var('v'), var('min')),
                        [assign('min', var('v'))]),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('min')),
        ]
        num_bytes = bytearray()
        for v in numbers:
            num_bytes.extend(struct.pack('<i', v))
        return self._compile_and_execute(stmts, memory_writes=[(work, bytes(num_bytes))])

    def gen_count_in_range(self) -> Optional[tuple[list[int], list[int]]]:
        """Count array elements in [lo, hi]."""
        n = self.rng.randint(3, 8)
        numbers = [self.rng.randint(-50, 50) for _ in range(n)]
        lo, hi = sorted(self.rng.sample(range(-30, 30), 2))
        work = 32768
        stmts = [
            assign('c', lit(0)), assign('i', lit(0)),
            while_loop(lt(var('i'), lit(n)), [
                assign('v', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                if_then(band(ge(var('v'), lit(lo)), le(var('v'), lit(hi))),
                        [assign('c', add(var('c'), lit(1)))]),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('c')),
        ]
        num_bytes = bytearray()
        for v in numbers:
            num_bytes.extend(struct.pack('<i', v))
        return self._compile_and_execute(stmts, memory_writes=[(work, bytes(num_bytes))])

    def gen_hash_string(self) -> Optional[tuple[list[int], list[int]]]:
        """djb2 hash."""
        length = self.rng.randint(1, 10)
        text = ''.join(self.rng.choices('abcdefghij', k=length))
        stmts = [
            assign('h', lit(5381)), assign('i', lit(0)),
            while_loop(ne(byte_at(var('i')), lit(0)), [
                assign('h', add(mul(var('h'), lit(33)), byte_at(var('i')))),
                assign('i', add(var('i'), lit(1))),
            ]),
            output_int(var('h')),
        ]
        return self._compile_and_execute(stmts, input_data=text.encode() + b'\x00')

    def gen_reverse_string(self) -> Optional[tuple[list[int], list[int]]]:
        """Reverse a string."""
        length = self.rng.randint(2, 8)
        text = ''.join(self.rng.choices('abcde12345', k=length))
        stmts = [
            assign('len', lit(0)),
            while_loop(ne(byte_at(var('len')), lit(0)),
                        [assign('len', add(var('len'), lit(1)))]),
            assign('i', sub(var('len'), lit(1))),
            while_loop(ge(var('i'), lit(0)), [
                output_char(byte_at(var('i'))),
                assign('i', sub(var('i'), lit(1))),
            ]),
        ]
        return self._compile_and_execute(stmts, input_data=text.encode() + b'\x00')

    def gen_uppercase(self) -> Optional[tuple[list[int], list[int]]]:
        """Uppercase a string."""
        length = self.rng.randint(2, 8)
        text = ''.join(self.rng.choices('abcde 123', k=length))
        stmts = [
            assign('i', lit(0)),
            while_loop(ne(byte_at(var('i')), lit(0)), [
                assign('ch', byte_at(var('i'))),
                if_then(band(ge(var('ch'), lit(97)), le(var('ch'), lit(122))),
                        [output_char(sub(var('ch'), lit(32)))],
                        [output_char(var('ch'))]),
                assign('i', add(var('i'), lit(1))),
            ]),
        ]
        return self._compile_and_execute(stmts, input_data=text.encode() + b'\x00')

    # ================================================================
    # TIER 5: Complex compositions (5% of dataset)
    # 50-200+ steps. Multiple constructs combined.
    # ================================================================

    def gen_sort_small(self) -> Optional[tuple[list[int], list[int]]]:
        """Insertion sort on 3-6 elements."""
        n = self.rng.randint(3, 6)
        numbers = [self.rng.randint(-30, 30) for _ in range(n)]
        work = 32768
        stmts = [
            assign('n', lit(n)), assign('i', lit(1)),
            while_loop(lt(var('i'), var('n')), [
                assign('key', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                assign('j', sub(var('i'), lit(1))),
                while_loop(
                    band(ge(var('j'), lit(0)),
                         gt(ByteLoad(add(lit(work), mul(var('j'), lit(4)))), var('key'))),
                    [
                        store_word(add(lit(work), mul(add(var('j'), lit(1)), lit(4))),
                                   ByteLoad(add(lit(work), mul(var('j'), lit(4))))),
                        assign('j', sub(var('j'), lit(1))),
                    ]),
                store_word(add(lit(work), mul(add(var('j'), lit(1)), lit(4))), var('key')),
                assign('i', add(var('i'), lit(1))),
            ]),
            assign('i', lit(0)),
            while_loop(lt(var('i'), var('n')), [
                output_int(ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                assign('i', add(var('i'), lit(1))),
            ]),
        ]
        num_bytes = bytearray()
        for v in numbers:
            num_bytes.extend(struct.pack('<i', v))
        return self._compile_and_execute(stmts, memory_writes=[(work, bytes(num_bytes))])

    def gen_is_prime(self) -> Optional[tuple[list[int], list[int]]]:
        """Check if n is prime."""
        n = self.rng.randint(2, 50)
        stmts = [
            assign('n', lit(n)),
            assign('result', lit(1)),
            if_then(le(var('n'), lit(1)),
                    [assign('result', lit(0))],
                    [
                        assign('i', lit(2)),
                        while_loop(
                            band(le(mul(var('i'), var('i')), var('n')),
                                 eq(var('result'), lit(1))),
                            [
                                if_then(eq(mod(var('n'), var('i')), lit(0)),
                                        [assign('result', lit(0))]),
                                assign('i', add(var('i'), lit(1))),
                            ]),
                    ]),
            output_int(var('result')),
        ]
        return self._compile_and_execute(stmts)

    def gen_sum_primes(self) -> Optional[tuple[list[int], list[int]]]:
        """Sum of primes up to n."""
        n = self.rng.randint(5, 20)
        stmts = [
            assign('total', lit(0)),
            assign('num', lit(2)),
            while_loop(le(var('num'), lit(n)), [
                assign('is_p', lit(1)),
                assign('d', lit(2)),
                while_loop(
                    band(le(mul(var('d'), var('d')), var('num')),
                         eq(var('is_p'), lit(1))),
                    [
                        if_then(eq(mod(var('num'), var('d')), lit(0)),
                                [assign('is_p', lit(0))]),
                        assign('d', add(var('d'), lit(1))),
                    ]),
                if_then(var('is_p'),
                        [assign('total', add(var('total'), var('num')))]),
                assign('num', add(var('num'), lit(1))),
            ]),
            output_int(var('total')),
        ]
        return self._compile_and_execute(stmts)

    # ================================================================
    # Dataset generation with curriculum
    # ================================================================

    # (name, generator, tier, weight)
    GENERATORS = [
        # Tier 1: Arithmetic (40%)
        ('add', 'gen_single_add', 1, 8),
        ('sub', 'gen_single_sub', 1, 6),
        ('mul', 'gen_single_mul', 1, 6),
        ('div', 'gen_single_div', 1, 4),
        ('mod', 'gen_single_mod', 1, 4),
        ('chain', 'gen_arithmetic_chain', 1, 4),
        ('expr', 'gen_expression', 1, 3),
        ('multi_out', 'gen_multi_output', 1, 3),
        ('edge', 'gen_edge_arithmetic', 1, 4),
        ('bitwise', 'gen_bitwise', 1, 3),
        # Tier 2: Conditionals (25%)
        ('cmp', 'gen_comparison', 2, 5),
        ('max_min', 'gen_max_min', 2, 4),
        ('abs', 'gen_abs_val', 2, 3),
        ('clamp', 'gen_clamp', 2, 3),
        ('sign', 'gen_sign', 2, 3),
        ('even_odd', 'gen_is_even_odd', 2, 3),
        ('multi_br', 'gen_multi_branch', 2, 3),
        # Tier 3: Loops (20%)
        ('loop_sum', 'gen_loop_sum', 3, 4),
        ('factorial', 'gen_factorial', 3, 3),
        ('power', 'gen_power', 3, 3),
        ('countdown', 'gen_countdown', 3, 2),
        ('fib', 'gen_fibonacci', 3, 3),
        ('gcd', 'gen_gcd', 3, 2),
        ('digits', 'gen_count_digits', 3, 2),
        ('sum_digits', 'gen_sum_digits', 3, 2),
        ('char_count', 'gen_char_count', 3, 2),
        ('word_count', 'gen_word_count', 3, 2),
        # Tier 4: Nested (10%)
        ('collatz', 'gen_collatz_steps', 4, 2),
        ('find_max', 'gen_find_max', 4, 2),
        ('find_min', 'gen_find_min', 4, 2),
        ('count_range', 'gen_count_in_range', 4, 2),
        ('hash', 'gen_hash_string', 4, 2),
        ('reverse', 'gen_reverse_string', 4, 1),
        ('upper', 'gen_uppercase', 4, 1),
        # Tier 5: Complex (5%)
        ('sort', 'gen_sort_small', 5, 2),
        ('is_prime', 'gen_is_prime', 5, 2),
        ('sum_primes', 'gen_sum_primes', 5, 1),
    ]

    def generate_dataset(self, n_samples: int,
                          max_trace_len: int = 2048) -> list[dict]:
        """
        Generate a training dataset using the "combined" curriculum strategy
        (Zaremba & Sutskever, 2014).
        """
        names = [g[0] for g in self.GENERATORS]
        funcs = [getattr(self, g[1]) for g in self.GENERATORS]
        weights = [g[3] for g in self.GENERATORS]

        dataset = []
        attempts = 0
        max_attempts = n_samples * 3

        while len(dataset) < n_samples and attempts < max_attempts:
            attempts += 1
            idx = self.rng.choices(range(len(funcs)), weights=weights, k=1)[0]

            try:
                result = funcs[idx]()
            except Exception:
                continue

            if result is None:
                continue

            prog_tokens, trace_tokens = result
            if len(trace_tokens) > max_trace_len:
                continue

            dataset.append({
                'program_tokens': prog_tokens,
                'trace_tokens': trace_tokens,
                'type': names[idx],
                'tier': self.GENERATORS[idx][2],
                'input_len': len(prog_tokens),
                'output_len': len(trace_tokens),
            })

        return dataset

    def generate_and_save(self, n_samples: int, path: str,
                           max_trace_len: int = 2048):
        """Generate dataset and save to disk."""
        import json
        dataset = self.generate_dataset(n_samples, max_trace_len)
        with open(path, 'w') as f:
            json.dump(dataset, f)
        return len(dataset)


if __name__ == '__main__':
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    gen = TrainingDataGenerator()
    dataset = gen.generate_dataset(n)

    # Stats
    tiers = {}
    types = {}
    total_prog = 0
    total_trace = 0
    for d in dataset:
        types[d['type']] = types.get(d['type'], 0) + 1
        tiers[d['tier']] = tiers.get(d['tier'], 0) + 1
        total_prog += d['input_len']
        total_trace += d['output_len']

    print(f"Generated {len(dataset)} samples")
    print(f"Avg program length: {total_prog / len(dataset):.0f} tokens")
    print(f"Avg trace length: {total_trace / len(dataset):.0f} tokens")
    print(f"\nTier distribution:")
    tier_names = {1: 'Arithmetic', 2: 'Conditionals', 3: 'Loops',
                  4: 'Nested', 5: 'Complex'}
    for t in sorted(tiers):
        pct = tiers[t] / len(dataset) * 100
        print(f"  Tier {t} ({tier_names[t]}): {tiers[t]} ({pct:.0f}%)")
    print(f"\nType distribution:")
    for t, c in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")
