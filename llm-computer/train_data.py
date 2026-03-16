"""
Training Data Generator for the Compute Model.

Generates (program_tokens, trace_tokens) pairs by:
1. Creating random WASM programs (arithmetic, fibonacci, sorting, string ops)
2. Executing them on the VM to get ground-truth traces
3. Encoding both as token sequences

The compute model learns: given program tokens → predict execution trace tokens.
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

    # ---- Program generators ----

    def gen_addition(self) -> Optional[tuple[list[int], list[int]]]:
        """Random addition: a + b."""
        a = self.rng.randint(-1000, 1000)
        b = self.rng.randint(-1000, 1000)
        code = make_addition_program(a, b)
        return self._execute(code)

    def gen_multiplication(self) -> Optional[tuple[list[int], list[int]]]:
        """Random multiplication: a * b."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        code = make_multiplication_program(a, b)
        return self._execute(code)

    def gen_fibonacci(self) -> Optional[tuple[list[int], list[int]]]:
        """Random fibonacci: fib(n) for n in [0, 25]."""
        n = self.rng.randint(0, 25)
        code = make_fibonacci_program(n)
        return self._execute(code, max_steps=500_000)

    def gen_arithmetic_chain(self) -> Optional[tuple[list[int], list[int]]]:
        """Chain of 2-5 arithmetic operations."""
        ops = [Op.I32_ADD, Op.I32_SUB, Op.I32_MUL]
        n_ops = self.rng.randint(2, 5)
        code = [Instruction(Op.I32_CONST, self.rng.randint(-50, 50))]
        for _ in range(n_ops):
            code.append(Instruction(Op.I32_CONST, self.rng.randint(-50, 50)))
            code.append(Instruction(self.rng.choice(ops)))
        code.append(Instruction(Op.OUTPUT))
        code.append(Instruction(Op.HALT))
        return self._execute(code)

    def gen_comparison(self) -> Optional[tuple[list[int], list[int]]]:
        """Random comparison: a op b → 0 or 1."""
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

    def gen_conditional(self) -> Optional[tuple[list[int], list[int]]]:
        """if (a > b) output a; else output b; (mini max)."""
        a = self.rng.randint(-100, 100)
        b = self.rng.randint(-100, 100)
        stmts = [
            assign('a', lit(a)),
            assign('b', lit(b)),
            if_then(
                gt(var('a'), var('b')),
                [output_int(var('a'))],
                [output_int(var('b'))],
            ),
        ]
        return self._compile_and_execute(stmts)

    def gen_loop_sum(self) -> Optional[tuple[list[int], list[int]]]:
        """Sum of 1..n for random n."""
        n = self.rng.randint(1, 50)
        stmts = [
            assign('sum', lit(0)),
            assign('i', lit(1)),
            while_loop(
                le(var('i'), lit(n)),
                [
                    assign('sum', add(var('sum'), var('i'))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('sum')),
        ]
        return self._compile_and_execute(stmts)

    def gen_factorial(self) -> Optional[tuple[list[int], list[int]]]:
        """Factorial of n (small n to avoid overflow)."""
        n = self.rng.randint(1, 10)
        stmts = [
            assign('result', lit(1)),
            assign('i', lit(2)),
            while_loop(
                le(var('i'), lit(n)),
                [
                    assign('result', mul(var('result'), var('i'))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('result')),
        ]
        return self._compile_and_execute(stmts)

    def gen_power(self) -> Optional[tuple[list[int], list[int]]]:
        """Compute base^exp for small values."""
        base = self.rng.randint(2, 5)
        exp = self.rng.randint(1, 8)
        stmts = [
            assign('result', lit(1)),
            assign('i', lit(0)),
            while_loop(
                lt(var('i'), lit(exp)),
                [
                    assign('result', mul(var('result'), lit(base))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('result')),
        ]
        return self._compile_and_execute(stmts)

    def gen_gcd(self) -> Optional[tuple[list[int], list[int]]]:
        """GCD via Euclidean algorithm."""
        a = self.rng.randint(1, 200)
        b = self.rng.randint(1, 200)
        stmts = [
            assign('a', lit(a)),
            assign('b', lit(b)),
            while_loop(
                ne(var('b'), lit(0)),
                [
                    assign('t', mod(var('a'), var('b'))),
                    assign('a', var('b')),
                    assign('b', var('t')),
                ]
            ),
            output_int(var('a')),
        ]
        return self._compile_and_execute(stmts)

    def gen_word_count(self) -> Optional[tuple[list[int], list[int]]]:
        """Count words in a random string."""
        words = ['hello', 'world', 'foo', 'bar', 'the', 'quick', 'brown',
                 'fox', 'jumps', 'over', 'lazy', 'dog', 'one', 'two', 'three']
        n_words = self.rng.randint(1, 8)
        text = ' '.join(self.rng.choices(words, k=n_words))

        stmts = [
            assign('count', lit(0)),
            assign('in_word', lit(0)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    if_then(
                        eq(var('ch'), lit(32)),
                        [if_then(var('in_word'), [
                            assign('count', add(var('count'), lit(1))),
                            assign('in_word', lit(0)),
                        ])],
                        [assign('in_word', lit(1))],
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            if_then(var('in_word'), [
                assign('count', add(var('count'), lit(1))),
            ]),
            output_int(var('count')),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._compile_and_execute(stmts, input_data=input_data)

    def gen_char_count(self) -> Optional[tuple[list[int], list[int]]]:
        """Count characters in a random string."""
        length = self.rng.randint(1, 30)
        text = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyz ', k=length))

        stmts = [
            assign('count', lit(0)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('count', add(var('count'), lit(1))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('count')),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._compile_and_execute(stmts, input_data=input_data)

    def gen_hash_string(self) -> Optional[tuple[list[int], list[int]]]:
        """djb2 hash of a random string."""
        length = self.rng.randint(1, 15)
        text = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyz', k=length))

        stmts = [
            assign('hash', lit(5381)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    assign('hash', add(mul(var('hash'), lit(33)), var('ch'))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('hash')),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._compile_and_execute(stmts, input_data=input_data)

    def gen_sort_small(self) -> Optional[tuple[list[int], list[int]]]:
        """Sort a small array (3-8 elements)."""
        n = self.rng.randint(3, 8)
        numbers = [self.rng.randint(-50, 50) for _ in range(n)]
        work = 32768  # WORK_BASE

        stmts = [
            assign('n', lit(n)),
            assign('i', lit(1)),
            while_loop(
                lt(var('i'), var('n')),
                [
                    assign('key', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                    assign('j', sub(var('i'), lit(1))),
                    while_loop(
                        BinOp('&',
                              ge(var('j'), lit(0)),
                              gt(ByteLoad(add(lit(work), mul(var('j'), lit(4)))), var('key'))),
                        [
                            store_word(
                                add(lit(work), mul(add(var('j'), lit(1)), lit(4))),
                                ByteLoad(add(lit(work), mul(var('j'), lit(4)))),
                            ),
                            assign('j', sub(var('j'), lit(1))),
                        ]
                    ),
                    store_word(
                        add(lit(work), mul(add(var('j'), lit(1)), lit(4))),
                        var('key'),
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            assign('i', lit(0)),
            while_loop(
                lt(var('i'), var('n')),
                [
                    output_int(ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
        ]

        num_bytes = bytearray()
        for val in numbers:
            num_bytes.extend(struct.pack('<i', val))
        memory_writes = [(work, bytes(num_bytes))]

        return self._compile_and_execute(stmts, memory_writes=memory_writes)

    def gen_reverse_string(self) -> Optional[tuple[list[int], list[int]]]:
        """Reverse a random string."""
        length = self.rng.randint(2, 12)
        text = ''.join(self.rng.choices('abcdefghijklmnopqrstuvwxyz', k=length))

        stmts = [
            assign('len', lit(0)),
            while_loop(
                ne(byte_at(var('len')), lit(0)),
                [assign('len', add(var('len'), lit(1)))],
            ),
            assign('i', sub(var('len'), lit(1))),
            while_loop(
                ge(var('i'), lit(0)),
                [
                    output_char(byte_at(var('i'))),
                    assign('i', sub(var('i'), lit(1))),
                ]
            ),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._compile_and_execute(stmts, input_data=input_data)

    def gen_to_uppercase(self) -> Optional[tuple[list[int], list[int]]]:
        """Uppercase a random string."""
        length = self.rng.randint(2, 12)
        text = ''.join(self.rng.choices('abcdefghij 123', k=length))

        stmts = [
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    if_then(
                        BinOp('&', ge(var('ch'), lit(97)), le(var('ch'), lit(122))),
                        [output_char(sub(var('ch'), lit(32)))],
                        [output_char(var('ch'))],
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._compile_and_execute(stmts, input_data=input_data)

    # ---- Dataset generation ----

    # Generator registry: (name, generator_func, weight)
    GENERATORS = [
        ('addition', 'gen_addition', 15),
        ('multiplication', 'gen_multiplication', 15),
        ('fibonacci', 'gen_fibonacci', 10),
        ('arithmetic_chain', 'gen_arithmetic_chain', 10),
        ('comparison', 'gen_comparison', 10),
        ('conditional', 'gen_conditional', 8),
        ('loop_sum', 'gen_loop_sum', 8),
        ('factorial', 'gen_factorial', 5),
        ('power', 'gen_power', 5),
        ('gcd', 'gen_gcd', 5),
        ('word_count', 'gen_word_count', 5),
        ('char_count', 'gen_char_count', 3),
        ('hash_string', 'gen_hash_string', 3),
        ('sort_small', 'gen_sort_small', 3),
        ('reverse_string', 'gen_reverse_string', 3),
        ('to_uppercase', 'gen_to_uppercase', 3),
    ]

    def generate_dataset(self, n_samples: int,
                          max_trace_len: int = 2048) -> list[dict]:
        """
        Generate a training dataset of (program, trace) pairs.

        Args:
            n_samples: number of samples to generate
            max_trace_len: maximum trace length (longer traces are skipped)

        Returns:
            list of dicts with 'program_tokens', 'trace_tokens', 'type'
        """
        # Build weighted choice list
        names = [g[0] for g in self.GENERATORS]
        funcs = [getattr(self, g[1]) for g in self.GENERATORS]
        weights = [g[2] for g in self.GENERATORS]

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
    types = {}
    total_prog = 0
    total_trace = 0
    for d in dataset:
        types[d['type']] = types.get(d['type'], 0) + 1
        total_prog += d['input_len']
        total_trace += d['output_len']

    print(f"Generated {len(dataset)} samples")
    print(f"Avg program length: {total_prog / len(dataset):.0f} tokens")
    print(f"Avg trace length: {total_trace / len(dataset):.0f} tokens")
    print(f"\nDistribution:")
    for t, c in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")
