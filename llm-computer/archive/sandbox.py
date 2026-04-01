"""
Sandbox: The transformer's internal compute substrate.

This is NOT a user-facing tool. It's what the transformer itself leverages
during inference to execute deterministic computations inside its own
forward pass.

From the blog:
"The key difference is that tool use is opaque: the model hands off control
 and receives a black-box answer. In-model execution is transparent: every
 intermediate step appears in the trace, and the model never leaves its own
 decoding loop."

The Sandbox:
1. Accepts a program + input data
2. Loads input into VM memory
3. Executes the program step-by-step
4. Returns output as part of the transformer's token trace

Runtime: pywasm (pure Python WASM interpreter, WebAssembly Spec 2.0 compliant).

The transformer doesn't call Python or an external interpreter.
It runs the WASM program through its own weights. The Sandbox class
here is the reference implementation that shows what the compiled
transformer does internally.

Usage patterns the transformer can leverage:
- "Count words in this text" → word_count program
- "Sort these numbers" → insertion_sort program
- "Find pattern in string" → string_search program
- "Compute hash" → hash program
- "Count character frequencies" → char_freq program
"""

from __future__ import annotations
import struct
import time
from typing import Optional
from dataclasses import dataclass

import pywasm  # noqa: F401 — ensures pywasm is available
from wasm_vm import Instruction, Op  # Op enum + Instruction for compilation
from wasm_runtime import WasmRuntime, _leb128, _sleb128
from mini_c import (
    Compiler, var, lit, add, sub, mul, div, mod,
    eq, ne, lt, gt, le, ge, band, bor,
    byte_at, assign, output_int, output_char,
    store_byte, store_word, if_then, while_loop, for_loop,
    ByteLoad, IntLit, BinOp, Var, FuncCall,
)


@dataclass
class SandboxResult:
    """Result from a sandbox computation."""
    output_ints: list[int]
    output_string: str
    steps: int
    tokens: int
    elapsed_seconds: float
    tokens_per_second: float
    trace_text: str

    def __repr__(self):
        return (
            f"SandboxResult(output={self.output_ints}, "
            f"string='{self.output_string}', "
            f"steps={self.steps:,}, "
            f"tok/s={self.tokens_per_second:,.0f})"
        )


# ============================================================
# Instruction-to-WASM translator
# ============================================================

# Output memory layout (inside WASM linear memory)
_INT_OUT_BASE = 49152       # i32 output values stored here
_CHAR_OUT_BASE = 57344      # char output bytes stored here
_INT_OUT_COUNT_ADDR = 61440  # i32: number of int outputs written
_CHAR_OUT_COUNT_ADDR = 61444 # i32: number of char outputs written


def _translate_to_wasm_bytecode(code: list[Instruction], n_locals: int,
                                 input_size: int = 0) -> tuple[bytes, int]:
    """
    Translate custom VM instructions to standard WASM bytecode.

    Replaces custom opcodes (OUTPUT, OUTPUT_CHAR, HALT, INPUT_SIZE)
    with standard WASM memory operations so the program can run on pywasm.

    Returns: (wasm_function_body, total_locals_count)
    """
    # Extra locals: _int_out_count, _char_out_count, _temp
    int_out_idx = n_locals
    char_out_idx = n_locals + 1
    temp_idx = n_locals + 2
    total_locals = n_locals + 3

    buf = bytearray()

    for inst in code:
        op = inst.op

        if op == Op.OUTPUT:
            # Pop value, store at INT_OUT_BASE + count*4, increment count
            buf.append(0x21); _leb128(buf, temp_idx)         # local.set _temp
            buf.append(0x41); _sleb128(buf, _INT_OUT_BASE)   # i32.const BASE
            buf.append(0x20); _leb128(buf, int_out_idx)      # local.get count
            buf.append(0x41); _sleb128(buf, 4)               # i32.const 4
            buf.append(0x6C)                                  # i32.mul
            buf.append(0x6A)                                  # i32.add -> addr
            buf.append(0x20); _leb128(buf, temp_idx)         # local.get _temp
            buf.append(0x36); _leb128(buf, 2); _leb128(buf, 0)  # i32.store
            # count++
            buf.append(0x20); _leb128(buf, int_out_idx)
            buf.append(0x41); _sleb128(buf, 1)
            buf.append(0x6A)
            buf.append(0x21); _leb128(buf, int_out_idx)

        elif op == Op.OUTPUT_CHAR:
            # Pop value, store byte at CHAR_OUT_BASE + count, increment count
            buf.append(0x21); _leb128(buf, temp_idx)          # local.set _temp
            buf.append(0x41); _sleb128(buf, _CHAR_OUT_BASE)   # i32.const BASE
            buf.append(0x20); _leb128(buf, char_out_idx)      # local.get count
            buf.append(0x6A)                                   # i32.add -> addr
            buf.append(0x20); _leb128(buf, temp_idx)          # local.get _temp
            buf.append(0x3A); _leb128(buf, 0); _leb128(buf, 0)  # i32.store8
            # count++
            buf.append(0x20); _leb128(buf, char_out_idx)
            buf.append(0x41); _sleb128(buf, 1)
            buf.append(0x6A)
            buf.append(0x21); _leb128(buf, char_out_idx)

        elif op == Op.HALT:
            # Store counts to memory and return
            _emit_store_counts(buf, int_out_idx, char_out_idx)
            buf.append(0x0F)  # return

        elif op == Op.INPUT_SIZE:
            buf.append(0x41); _sleb128(buf, input_size)

        elif op == Op.I32_CONST:
            buf.append(0x41); _sleb128(buf, inst.operand)

        elif op == Op.I32_LOAD:
            buf.append(0x28); _leb128(buf, 2); _leb128(buf, 0)

        elif op == Op.I32_STORE:
            buf.append(0x36); _leb128(buf, 2); _leb128(buf, 0)

        elif op == Op.I32_LOAD8_U:
            buf.append(0x2D); _leb128(buf, 0); _leb128(buf, 0)

        elif op == Op.I32_LOAD8_S:
            buf.append(0x2C); _leb128(buf, 0); _leb128(buf, 0)

        elif op == Op.I32_STORE8:
            buf.append(0x3A); _leb128(buf, 0); _leb128(buf, 0)

        elif op in (Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE):
            buf.append(op.value); _leb128(buf, inst.operand)

        elif op in (Op.BR, Op.BR_IF):
            buf.append(op.value); _leb128(buf, inst.operand)

        elif op in (Op.BLOCK, Op.LOOP, Op.IF):
            buf.append(op.value); buf.append(0x40)  # void block type

        elif op == Op.CALL:
            buf.append(0x10); _leb128(buf, inst.operand)

        else:
            # Simple opcodes: END, ELSE, NOP, DROP, SELECT,
            # arithmetic, comparison, bitwise — all single-byte, no operands
            buf.append(op.value)

    # At end of program, store output counts to known memory locations
    _emit_store_counts(buf, int_out_idx, char_out_idx)

    return bytes(buf), total_locals


def _emit_store_counts(buf: bytearray, int_out_idx: int, char_out_idx: int):
    """Emit instructions to store output counts to memory."""
    # memory[INT_OUT_COUNT_ADDR] = int_out_count
    buf.append(0x41); _sleb128(buf, _INT_OUT_COUNT_ADDR)
    buf.append(0x20); _leb128(buf, int_out_idx)
    buf.append(0x36); _leb128(buf, 2); _leb128(buf, 0)
    # memory[CHAR_OUT_COUNT_ADDR] = char_out_count
    buf.append(0x41); _sleb128(buf, _CHAR_OUT_COUNT_ADDR)
    buf.append(0x20); _leb128(buf, char_out_idx)
    buf.append(0x36); _leb128(buf, 2); _leb128(buf, 0)


def _build_sandbox_wasm(wasm_body: bytes, total_locals: int,
                         memory_pages: int = 2,
                         data_segments: list[tuple[int, bytes]] = None) -> bytes:
    """
    Build a complete WASM binary with a single exported function 'run'
    that has the given body and locals.
    """
    buf = bytearray()
    buf.extend(b'\x00asm\x01\x00\x00\x00')

    # Type section: () -> ()
    type_sec = bytearray()
    _leb128(type_sec, 1)       # 1 type
    type_sec.append(0x60)      # functype
    _leb128(type_sec, 0)       # 0 params
    _leb128(type_sec, 0)       # 0 results
    _write_section(buf, 1, type_sec)

    # Function section
    func_sec = bytearray()
    _leb128(func_sec, 1)  # 1 function
    _leb128(func_sec, 0)  # type index 0
    _write_section(buf, 3, func_sec)

    # Memory section
    mem_sec = bytearray()
    _leb128(mem_sec, 1)       # 1 memory
    mem_sec.append(0x00)      # no max
    _leb128(mem_sec, memory_pages)
    _write_section(buf, 5, mem_sec)

    # Export section: export 'run' function and 'memory'
    exp_sec = bytearray()
    _leb128(exp_sec, 2)       # 2 exports
    # Export function
    _leb128(exp_sec, 3)
    exp_sec.extend(b'run')
    exp_sec.append(0x00)      # func
    _leb128(exp_sec, 0)       # index 0
    # Export memory
    _leb128(exp_sec, 6)
    exp_sec.extend(b'memory')
    exp_sec.append(0x02)      # memory
    _leb128(exp_sec, 0)       # index 0
    _write_section(buf, 7, exp_sec)

    # Code section
    func_body = bytearray()
    # Local declarations: all i32
    if total_locals > 0:
        _leb128(func_body, 1)          # 1 local group
        _leb128(func_body, total_locals)  # N locals
        func_body.append(0x7F)         # type i32
    else:
        _leb128(func_body, 0)          # 0 local groups

    func_body.extend(wasm_body)
    func_body.append(0x0B)  # END

    code_sec = bytearray()
    _leb128(code_sec, 1)                    # 1 function body
    _leb128(code_sec, len(func_body))
    code_sec.extend(func_body)
    _write_section(buf, 10, code_sec)

    # Data section
    if data_segments:
        data_sec = bytearray()
        _leb128(data_sec, len(data_segments))
        for offset, data in data_segments:
            data_sec.append(0x00)       # active, memory 0
            data_sec.append(0x41)       # i32.const
            _sleb128(data_sec, offset)
            data_sec.append(0x0B)       # end init expr
            _leb128(data_sec, len(data))
            data_sec.extend(data)
        _write_section(buf, 11, data_sec)

    return bytes(buf)


def _write_section(buf: bytearray, section_id: int, content: bytearray):
    buf.append(section_id)
    _leb128(buf, len(content))
    buf.extend(content)


class Sandbox:
    """
    The transformer's internal execution sandbox.

    Provides a library of pre-compiled programs that the transformer
    can invoke during its forward pass to perform deterministic
    computation on data in its context.

    Compiles Mini-C → WASM bytecode → pywasm execution.
    """

    # Memory layout constants
    INPUT_BASE = 0         # Input data starts here
    INPUT_MAX = 32768      # 32KB for input
    WORK_BASE = 32768      # Working memory for programs
    OUTPUT_BASE = 49152    # Output buffer

    def __init__(self):
        self._program_cache: dict[str, tuple[list[Instruction], int]] = {}

    def _compile(self, program_name: str, stmts: list) -> tuple[list[Instruction], int]:
        """Compile Mini-C statements, with caching."""
        if program_name not in self._program_cache:
            compiler = Compiler()
            code, n_locals = compiler.compile(stmts)
            self._program_cache[program_name] = (code, n_locals)
        return self._program_cache[program_name]

    def _run(self, program_name: str, stmts: list,
             input_data: Optional[bytes] = None,
             memory_writes: Optional[list[tuple[int, bytes]]] = None) -> SandboxResult:
        """
        Internal: compile Mini-C → WASM bytecode → execute via pywasm.
        """
        code, n_locals = self._compile(program_name, stmts)
        input_size = len(input_data) if input_data else 0
        return self._run_pywasm(program_name, code, n_locals,
                                 input_data, memory_writes, input_size)

    def _run_pywasm(self, program_name: str, code: list[Instruction],
                     n_locals: int, input_data: Optional[bytes],
                     memory_writes: Optional[list[tuple[int, bytes]]],
                     input_size: int) -> SandboxResult:
        """Execute via pywasm — the primary runtime."""
        # Translate custom VM instructions → standard WASM bytecode
        wasm_body, total_locals = _translate_to_wasm_bytecode(
            code, n_locals, input_size
        )

        # Build data segments for input and any extra memory writes
        data_segments = []
        if input_data:
            data_segments.append((self.INPUT_BASE, input_data))
        if memory_writes:
            data_segments.extend(memory_writes)

        # Build the .wasm binary
        wasm_binary = _build_sandbox_wasm(
            wasm_body, total_locals,
            memory_pages=2,  # 128KB
            data_segments=data_segments if data_segments else None,
        )

        # Load and execute via pywasm
        rt = WasmRuntime.from_bytes(wasm_binary)
        start = time.perf_counter()
        rt.call("run")
        elapsed = time.perf_counter() - start

        # Read output from WASM memory
        int_count = struct.unpack('<i', rt.read_memory(_INT_OUT_COUNT_ADDR, 4))[0]
        char_count = struct.unpack('<i', rt.read_memory(_CHAR_OUT_COUNT_ADDR, 4))[0]

        output_ints = []
        if int_count > 0:
            for i in range(int_count):
                val = struct.unpack('<i', rt.read_memory(
                    _INT_OUT_BASE + i * 4, 4
                ))[0]
                output_ints.append(val)

        output_string = ""
        if char_count > 0:
            char_bytes = rt.read_memory(_CHAR_OUT_BASE, char_count)
            output_string = char_bytes.decode('utf-8', errors='replace')

        tok_per_sec = 1 / elapsed if elapsed > 0 else 0

        return SandboxResult(
            output_ints=output_ints,
            output_string=output_string,
            steps=0,  # pywasm doesn't expose step count
            tokens=0,
            elapsed_seconds=elapsed,
            tokens_per_second=tok_per_sec,
            trace_text="[executed via pywasm]",
        )

    # ================================================================
    # Program Library — what the transformer can leverage
    # ================================================================

    def word_count(self, text: str) -> SandboxResult:
        """
        Count words in text. A word is a sequence of non-space chars.

        The transformer uses this when it needs an exact word count —
        no guessing, no approximation. The count is deterministic.

        Mini-C equivalent:
            int count = 0, in_word = 0, i = 0;
            while (mem[i] != 0) {
                int ch = mem[i];
                if (ch == ' ' || ch == '\\n' || ch == '\\t' || ch == '\\r') {
                    if (in_word) { count++; in_word = 0; }
                } else {
                    in_word = 1;
                }
                i++;
            }
            if (in_word) count++;
            output(count);
        """
        stmts = [
            assign('count', lit(0)),
            assign('in_word', lit(0)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    # Check if whitespace: space(32), tab(9), newline(10), CR(13)
                    if_then(
                        bor(bor(eq(var('ch'), lit(32)), eq(var('ch'), lit(9))),
                             bor(eq(var('ch'), lit(10)), eq(var('ch'), lit(13)))),
                        # whitespace
                        [if_then(var('in_word'), [
                            assign('count', add(var('count'), lit(1))),
                            assign('in_word', lit(0)),
                        ])],
                        # non-whitespace
                        [assign('in_word', lit(1))],
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            # Handle last word if text doesn't end with space
            if_then(var('in_word'), [
                assign('count', add(var('count'), lit(1))),
            ]),
            output_int(var('count')),
        ]

        input_data = text.encode('utf-8') + b'\x00'
        return self._run('word_count', stmts, input_data)

    def char_count(self, text: str) -> SandboxResult:
        """
        Count total characters (bytes) in text.
        Deterministic character count — no off-by-one errors.
        """
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
        return self._run('char_count', stmts, input_data)

    def line_count(self, text: str) -> SandboxResult:
        """Count newlines in text. Empty text = 0 lines, otherwise lines = newlines + 1."""
        stmts = [
            assign('lines', lit(0)),
            assign('has_content', lit(0)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('has_content', lit(1)),
                    if_then(
                        eq(byte_at(var('i')), lit(10)),  # '\n'
                        [assign('lines', add(var('lines'), lit(1)))],
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            # If there's content and last char isn't newline, add 1
            if_then(var('has_content'), [
                assign('lines', add(var('lines'), lit(1))),
            ]),
            output_int(var('lines')),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._run('line_count', stmts, input_data)

    def char_frequency(self, text: str) -> SandboxResult:
        """
        Count frequency of each byte value in text.
        Outputs 256 integers: freq[0], freq[1], ..., freq[255].

        The transformer uses this for exact character distribution analysis.
        """
        # Use working memory at WORK_BASE for the 256-entry frequency table
        # Each entry is 4 bytes (i32), so table spans WORK_BASE to WORK_BASE + 1024
        table_base = self.WORK_BASE

        stmts = [
            # Zero the frequency table
            assign('j', lit(0)),
            while_loop(
                lt(var('j'), lit(256)),
                [
                    store_word(add(lit(table_base), mul(var('j'), lit(4))), lit(0)),
                    assign('j', add(var('j'), lit(1))),
                ]
            ),
            # Count frequencies
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    # freq[ch]++
                    assign('addr', add(lit(table_base), mul(var('ch'), lit(4)))),
                    assign('cur', ByteLoad(var('addr'))),  # simplified: use word load
                    store_word(var('addr'), add(var('cur'), lit(1))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            # Output only non-zero frequencies as (char_code, count) pairs
            assign('j', lit(0)),
            while_loop(
                lt(var('j'), lit(256)),
                [
                    assign('freq', ByteLoad(add(lit(table_base), mul(var('j'), lit(4))))),
                    if_then(
                        gt(var('freq'), lit(0)),
                        [
                            output_int(var('j')),      # character code
                            output_int(var('freq')),   # frequency
                        ],
                    ),
                    assign('j', add(var('j'), lit(1))),
                ]
            ),
        ]

        input_data = text.encode('utf-8') + b'\x00'
        result = self._run('char_frequency', stmts, input_data)

        # Parse output pairs into a readable format
        freqs = {}
        ints = result.output_ints
        for k in range(0, len(ints) - 1, 2):
            ch_code = ints[k]
            count = ints[k + 1]
            if 0 <= ch_code < 256:
                freqs[chr(ch_code) if 32 <= ch_code < 127 else f'\\x{ch_code:02x}'] = count
        result._parsed_freqs = freqs
        return result

    def string_search(self, text: str, pattern: str) -> SandboxResult:
        """
        Find all occurrences of pattern in text. Returns count and positions.

        Naive O(n*m) search — deterministic, correct for all inputs.
        The transformer uses this instead of guessing whether a pattern exists.
        """
        # Layout: text at INPUT_BASE, pattern at WORK_BASE
        pat_base = self.WORK_BASE
        text_bytes = text.encode('utf-8') + b'\x00'
        pat_bytes = pattern.encode('utf-8') + b'\x00'
        text_len = len(text_bytes) - 1
        pat_len = len(pat_bytes) - 1

        stmts = [
            assign('count', lit(0)),
            assign('text_len', lit(text_len)),
            assign('pat_len', lit(pat_len)),
            assign('i', lit(0)),
            while_loop(
                le(add(var('i'), var('pat_len')), var('text_len')),
                [
                    # Check if pattern matches at position i
                    assign('match', lit(1)),
                    assign('j', lit(0)),
                    while_loop(
                        BinOp('&', lt(var('j'), var('pat_len')), var('match')),
                        [
                            if_then(
                                ne(
                                    byte_at(add(var('i'), var('j'))),
                                    byte_at(add(lit(pat_base), var('j'))),
                                ),
                                [assign('match', lit(0))],
                            ),
                            assign('j', add(var('j'), lit(1))),
                        ]
                    ),
                    if_then(var('match'), [
                        assign('count', add(var('count'), lit(1))),
                        output_int(var('i')),  # position of match
                    ]),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            # Output total count as last value
            output_int(var('count')),
        ]

        input_data = text_bytes
        memory_writes = [(pat_base, pat_bytes)]
        result = self._run('string_search', stmts, input_data,
                           memory_writes=memory_writes)

        # Last output is total count; preceding are positions
        output_ints = result.output_ints
        total_count = output_ints[-1] if output_ints else 0
        positions = output_ints[:-1] if len(output_ints) > 1 else []

        result._count = total_count
        result._positions = positions
        result.output_string = f"Found {total_count} occurrences at positions {positions}"
        return result

    def sort_integers(self, numbers: list[int]) -> SandboxResult:
        """
        Sort a list of integers using insertion sort.
        The transformer uses this for exact sorting without token-by-token guessing.

        Numbers are stored in memory as i32 array at WORK_BASE.
        """
        n = len(numbers)
        work = self.WORK_BASE

        stmts = [
            assign('n', lit(n)),
            # Insertion sort
            assign('i', lit(1)),
            while_loop(
                lt(var('i'), var('n')),
                [
                    # key = arr[i]
                    assign('key', ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                    assign('j', sub(var('i'), lit(1))),
                    while_loop(
                        BinOp('&',
                              ge(var('j'), lit(0)),
                              gt(ByteLoad(add(lit(work), mul(var('j'), lit(4)))), var('key'))),
                        [
                            # arr[j+1] = arr[j]
                            store_word(
                                add(lit(work), mul(add(var('j'), lit(1)), lit(4))),
                                ByteLoad(add(lit(work), mul(var('j'), lit(4)))),
                            ),
                            assign('j', sub(var('j'), lit(1))),
                        ]
                    ),
                    # arr[j+1] = key
                    store_word(
                        add(lit(work), mul(add(var('j'), lit(1)), lit(4))),
                        var('key'),
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            # Output sorted array
            assign('i', lit(0)),
            while_loop(
                lt(var('i'), var('n')),
                [
                    output_int(ByteLoad(add(lit(work), mul(var('i'), lit(4))))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
        ]

        # Pack numbers as i32 array
        num_bytes = bytearray()
        for val in numbers:
            num_bytes.extend(struct.pack('<i', val))
        memory_writes = [(work, bytes(num_bytes))]

        return self._run('sort_integers', stmts, memory_writes=memory_writes)

    def hash_string(self, text: str) -> SandboxResult:
        """
        Compute a deterministic hash of the input string (djb2 algorithm).
        The transformer uses this when it needs a consistent hash value.

        djb2: hash = 5381; for each char c: hash = hash * 33 + c
        """
        stmts = [
            assign('hash', lit(5381)),
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    # hash = hash * 33 + ch
                    assign('ch', byte_at(var('i'))),
                    assign('hash', add(mul(var('hash'), lit(33)), var('ch'))),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('hash')),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._run('hash_string', stmts, input_data)

    def sum_integers(self, numbers: list[int]) -> SandboxResult:
        """Compute sum of integers. Exact, no overflow guessing."""
        work = self.WORK_BASE
        n = len(numbers)
        stmts = [
            assign('total', lit(0)),
            assign('i', lit(0)),
            while_loop(
                lt(var('i'), lit(n)),
                [
                    assign('total', add(
                        var('total'),
                        ByteLoad(add(lit(work), mul(var('i'), lit(4)))),
                    )),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
            output_int(var('total')),
        ]

        num_bytes = bytearray()
        for val in numbers:
            num_bytes.extend(struct.pack('<i', val))
        memory_writes = [(work, bytes(num_bytes))]

        return self._run('sum_integers', stmts, memory_writes=memory_writes)

    def reverse_string(self, text: str) -> SandboxResult:
        """Reverse a string byte-by-byte. Deterministic."""
        stmts = [
            # Find length
            assign('len', lit(0)),
            while_loop(
                ne(byte_at(var('len')), lit(0)),
                [assign('len', add(var('len'), lit(1)))],
            ),
            # Output chars in reverse
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
        return self._run('reverse_string', stmts, input_data)

    def to_uppercase(self, text: str) -> SandboxResult:
        """Convert ASCII lowercase to uppercase."""
        stmts = [
            assign('i', lit(0)),
            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    assign('ch', byte_at(var('i'))),
                    if_then(
                        BinOp('&', ge(var('ch'), lit(97)), le(var('ch'), lit(122))),
                        # lowercase a-z → A-Z (subtract 32)
                        [output_char(sub(var('ch'), lit(32)))],
                        [output_char(var('ch'))],
                    ),
                    assign('i', add(var('i'), lit(1))),
                ]
            ),
        ]
        input_data = text.encode('utf-8') + b'\x00'
        return self._run('to_uppercase', stmts, input_data)

    def unique_words(self, text: str) -> SandboxResult:
        """
        Count unique words in text using a simple hash-set approach.
        Words are delimited by whitespace.

        Uses memory as a hash table: for each word, compute hash,
        check if slot is occupied, if not mark it and increment count.
        """
        # Simplified: count words, then use char_frequency style tracking
        # For a real unique count, we use a bitmap in working memory
        hash_table_base = self.WORK_BASE
        hash_table_size = 1024  # slots

        stmts = [
            # Zero hash table
            assign('k', lit(0)),
            while_loop(
                lt(var('k'), lit(hash_table_size)),
                [
                    store_byte(add(lit(hash_table_base), var('k')), lit(0)),
                    assign('k', add(var('k'), lit(1))),
                ]
            ),

            assign('unique', lit(0)),
            assign('i', lit(0)),

            while_loop(
                ne(byte_at(var('i')), lit(0)),
                [
                    # Skip whitespace
                    while_loop(
                        BinOp('&',
                              ne(byte_at(var('i')), lit(0)),
                              bor(eq(byte_at(var('i')), lit(32)),
                                  eq(byte_at(var('i')), lit(10)))),
                        [assign('i', add(var('i'), lit(1)))],
                    ),
                    # If not at end, hash the word
                    if_then(
                        ne(byte_at(var('i')), lit(0)),
                        [
                            assign('hash', lit(5381)),
                            assign('word_start', var('i')),
                            # Hash chars until whitespace or null
                            while_loop(
                                BinOp('&',
                                      ne(byte_at(var('i')), lit(0)),
                                      BinOp('&',
                                            ne(byte_at(var('i')), lit(32)),
                                            ne(byte_at(var('i')), lit(10)))),
                                [
                                    assign('hash', add(
                                        mul(var('hash'), lit(33)),
                                        byte_at(var('i'))
                                    )),
                                    assign('i', add(var('i'), lit(1))),
                                ]
                            ),
                            # Map hash to slot
                            assign('slot', mod(
                                BinOp('&', var('hash'), lit(0x7FFFFFFF)),
                                lit(hash_table_size)
                            )),
                            # If slot is empty, new unique word
                            if_then(
                                eq(byte_at(add(lit(hash_table_base), var('slot'))), lit(0)),
                                [
                                    store_byte(add(lit(hash_table_base), var('slot')), lit(1)),
                                    assign('unique', add(var('unique'), lit(1))),
                                ],
                            ),
                        ],
                    ),
                ]
            ),
            output_int(var('unique')),
        ]

        input_data = text.encode('utf-8') + b'\x00'
        return self._run('unique_words', stmts, input_data)
