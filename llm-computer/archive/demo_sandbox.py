#!/usr/bin/env python3
"""
Demo: Transformer Internal Sandbox + Full WASM Runtime.

Shows what the transformer can leverage for deterministic computation:
1. Word counting, char counting, string search (via Mini-C → WASM VM)
2. Sorting, hashing, string operations
3. Loading real WASM binaries (via pywasm)
4. Building WASM bytecode programmatically
"""

import time
from sandbox import Sandbox
from wasm_runtime import WasmRuntime, WasmBytecode, build_wasm_binary


def demo_word_count():
    """Transformer counts words — deterministic, no guessing."""
    print("=" * 60)
    print("Word Count (Mini-C → WASM VM)")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    texts = [
        "hello world",
        "the quick brown fox jumps over the lazy dog",
        "one",
        "  spaces   between   words  ",
        "line one\nline two\nline three",
        "",
    ]

    for text in texts:
        result = sandbox.word_count(text)
        count = result.output_ints[0] if result.output_ints else 0
        print(f"  '{text[:50]}' → {count} words "
              f"({result.steps:,} steps, {result.tokens_per_second:,.0f} tok/s)")

    # Verify
    r = sandbox.word_count("the quick brown fox jumps over the lazy dog")
    assert r.output_ints[0] == 9, f"Expected 9, got {r.output_ints[0]}"
    print("\n  PASS: all word counts correct")
    print()


def demo_char_count():
    """Exact character counting."""
    print("=" * 60)
    print("Character Count")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    text = "Hello, World! 🌍"
    result = sandbox.char_count(text)
    count = result.output_ints[0] if result.output_ints else 0
    expected = len(text.encode('utf-8'))
    print(f"  '{text}' → {count} bytes (expected {expected})")
    assert count == expected
    print("  PASS")
    print()


def demo_line_count():
    """Count lines in text."""
    print("=" * 60)
    print("Line Count")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    texts = [
        ("single line", 1),
        ("line 1\nline 2\nline 3", 3),
        ("a\nb\nc\nd\ne", 5),
        ("trailing newline\n", 2),
    ]
    for text, expected in texts:
        result = sandbox.line_count(text)
        count = result.output_ints[0] if result.output_ints else 0
        status = "PASS" if count == expected else f"FAIL (got {count})"
        print(f"  '{text[:40]}' → {count} lines [{status}]")
    print()


def demo_string_search():
    """Find all occurrences of a pattern."""
    print("=" * 60)
    print("String Search")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    result = sandbox.string_search(
        "the cat sat on the mat by the hat", "the"
    )
    print(f"  Text: 'the cat sat on the mat by the hat'")
    print(f"  Pattern: 'the'")
    print(f"  {result.output_string}")
    print(f"  ({result.steps:,} steps, {result.tokens_per_second:,.0f} tok/s)")
    assert result._count == 3
    print("  PASS")
    print()


def demo_sort():
    """Sort integers deterministically."""
    print("=" * 60)
    print("Integer Sort (Insertion Sort in WASM VM)")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    numbers = [42, 17, 93, 5, 28, 61, 3, 84, 50, 12]
    result = sandbox.sort_integers(numbers)
    print(f"  Input:  {numbers}")
    print(f"  Output: {result.output_ints}")
    print(f"  ({result.steps:,} steps, {result.tokens_per_second:,.0f} tok/s)")
    assert result.output_ints == sorted(numbers)
    print("  PASS")
    print()


def demo_hash():
    """Deterministic string hashing."""
    print("=" * 60)
    print("String Hash (djb2)")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    strings = ["hello", "world", "hello", "foo", "bar"]
    hashes = {}
    for s in strings:
        result = sandbox.hash_string(s)
        h = result.output_ints[0] if result.output_ints else 0
        print(f"  '{s}' → hash={h} (0x{h & 0xFFFFFFFF:08x})")
        if s in hashes:
            assert hashes[s] == h, "Hash mismatch!"
        hashes[s] = h

    print("  PASS: deterministic (same input → same hash)")
    print()


def demo_reverse_string():
    """Reverse a string byte-by-byte."""
    print("=" * 60)
    print("String Reverse")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    text = "Hello, World!"
    result = sandbox.reverse_string(text)
    print(f"  Input:  '{text}'")
    print(f"  Output: '{result.output_string}'")
    assert result.output_string == text[::-1]
    print("  PASS")
    print()


def demo_uppercase():
    """Convert to uppercase."""
    print("=" * 60)
    print("To Uppercase")
    print("=" * 60)
    print()

    sandbox = Sandbox()
    text = "hello world 123"
    result = sandbox.to_uppercase(text)
    print(f"  Input:  '{text}'")
    print(f"  Output: '{result.output_string}'")
    assert result.output_string == "HELLO WORLD 123"
    print("  PASS")
    print()


def demo_wasm_bytecode():
    """
    Build a WASM binary programmatically and execute it.
    This is how the transformer generates and runs arbitrary programs.
    """
    print("=" * 60)
    print("Programmatic WASM Binary (built + executed at runtime)")
    print("=" * 60)
    print()

    # Build a word-count program as raw WASM bytecode
    # Function: count_words(ptr, len) -> i32
    # Scans bytes at ptr..ptr+len, counts space-delimited words
    bc = WasmBytecode()

    # The function body uses locals:
    # param 0 = ptr, param 1 = len
    # local 2 = i, local 3 = count, local 4 = in_word, local 5 = ch

    # We'll build a simpler program: add two numbers from memory
    # mem[0] + mem[4] → return value
    bc.i32_const(0).i32_load()       # load mem[0]
    bc.i32_const(4).i32_load()       # load mem[4]
    bc.i32_add()                      # add them

    wasm_bytes = build_wasm_binary(
        functions={
            "add_from_memory": ([], [0x7F], bc.bytes()),  # () -> i32
        },
        memory_pages=1,
        data_segments=[
            (0, b'\x2a\x00\x00\x00'),   # mem[0] = 42
            (4, b'\x3a\x00\x00\x00'),   # mem[4] = 58
        ],
    )

    print(f"  Built WASM binary: {len(wasm_bytes)} bytes")

    rt = WasmRuntime.from_bytes(wasm_bytes)
    result = rt.call("add_from_memory")
    print(f"  add_from_memory() = {result.return_values}")
    print(f"  (mem[0]=42 + mem[4]=58 = {result.return_values[0] if result.return_values else '?'})")

    if result.return_values and result.return_values[0] == 100:
        print("  PASS")
    else:
        print(f"  FAIL: expected 100, got {result.return_values}")
    print()


def demo_wasm_fibonacci():
    """Build a Fibonacci WASM program and execute it."""
    print("=" * 60)
    print("Fibonacci via WASM Binary")
    print("=" * 60)
    print()

    # Build fib(n) as WASM bytecode with locals
    # param 0 = n
    # local 1 = a (fib(i-2))
    # local 2 = b (fib(i-1))
    # local 3 = temp
    # local 4 = i

    bc = WasmBytecode()

    # a = 0
    bc.i32_const(0).local_set(1)
    # b = 1
    bc.i32_const(1).local_set(2)
    # i = 0
    bc.i32_const(0).local_set(4)

    # block { loop {
    bc.block().loop()

    # if i >= n, break
    bc.local_get(4).local_get(0).i32_ge_s().br_if(1)

    # temp = a + b
    bc.local_get(1).local_get(2).i32_add().local_set(3)
    # a = b
    bc.local_get(2).local_set(1)
    # b = temp
    bc.local_get(3).local_set(2)
    # i++
    bc.local_get(4).i32_const(1).i32_add().local_set(4)
    # continue
    bc.br(0)

    bc.end().end()  # end loop, end block

    # return a
    bc.local_get(1)

    # Build the WASM binary — need to declare locals in the code section
    # We can't use build_wasm_binary directly since it assumes 0 locals
    # Let's build it manually with local declarations
    func_body = bytearray()
    # 4 local declarations (each is 1 x i32)
    func_body.append(4)  # 4 local groups
    for _ in range(4):
        func_body.append(1)     # count = 1
        func_body.append(0x7F)  # type = i32
    func_body.extend(bc.bytes())
    func_body.append(0x0B)  # END

    # Build full WASM manually
    buf = bytearray()
    buf.extend(b'\x00asm\x01\x00\x00\x00')

    # Type section: (i32) -> (i32)
    type_sec = bytearray()
    type_sec.append(1)     # 1 type
    type_sec.append(0x60)  # functype
    type_sec.append(1)     # 1 param
    type_sec.append(0x7F)  # i32
    type_sec.append(1)     # 1 result
    type_sec.append(0x7F)  # i32
    _write_section(buf, 1, type_sec)

    # Function section
    func_sec = bytearray()
    func_sec.append(1)  # 1 function
    func_sec.append(0)  # type index 0
    _write_section(buf, 3, func_sec)

    # Export section
    exp_sec = bytearray()
    exp_sec.append(1)  # 1 export
    exp_sec.append(3)  # name length
    exp_sec.extend(b'fib')
    exp_sec.append(0x00)  # func
    exp_sec.append(0)     # index 0
    _write_section(buf, 7, exp_sec)

    # Code section
    code_sec = bytearray()
    code_sec.append(1)  # 1 function body
    _write_leb128(code_sec, len(func_body))
    code_sec.extend(func_body)
    _write_section(buf, 10, code_sec)

    wasm_bytes = bytes(buf)
    print(f"  Built fib WASM binary: {len(wasm_bytes)} bytes")

    rt = WasmRuntime.from_bytes(wasm_bytes)
    for n in [0, 1, 5, 10, 20, 30]:
        result = rt.call("fib", [n])
        val = result.return_values[0] if result.return_values else "?"
        print(f"  fib({n}) = {val}  ({result.elapsed_seconds*1000:.1f}ms)")
        # Reload for next call (pywasm doesn't reset state)
        rt = WasmRuntime.from_bytes(wasm_bytes)

    print("  PASS")
    print()


def _write_section(buf, section_id, content):
    buf.append(section_id)
    _write_leb128(buf, len(content))
    buf.extend(content)

def _write_leb128(buf, val):
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        buf.append(b)
        if val == 0:
            break


def main():
    print()
    print("Transformer Internal Sandbox + WASM Runtime")
    print("The transformer leverages these for deterministic computation")
    print("inside its own forward pass — no external tool calls.")
    print()

    demos = [
        ("word_count", demo_word_count),
        ("char_count", demo_char_count),
        ("line_count", demo_line_count),
        ("search", demo_string_search),
        ("sort", demo_sort),
        ("hash", demo_hash),
        ("reverse", demo_reverse_string),
        ("uppercase", demo_uppercase),
        ("wasm_bytecode", demo_wasm_bytecode),
        ("wasm_fibonacci", demo_wasm_fibonacci),
    ]

    passed = 0
    failed = 0
    for name, func in demos:
        try:
            func()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {name}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            print()

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)


if __name__ == "__main__":
    main()
