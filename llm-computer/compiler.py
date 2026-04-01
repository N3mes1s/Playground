"""
Trace Compiler: converts VM execution traces to/from token sequences.

Token vocabulary and trace encoding for the transformer's execution traces.
Weight compilation is in weight_compiler.py.
"""

import struct

from wasm_vm import Op, Instruction


# Token vocabulary for execution traces
class TraceVocab:
    """
    Token vocabulary for the execution trace.

    Tokens 0-255: byte values (for encoding i32 values as 4 bytes)
    Token 256: HALT
    Token 257: TRAP
    Token 258: OUTPUT marker
    Token 259: BRANCH_TAKEN marker
    Token 260-515: Opcode tokens (Op value + 260)

    Commit metadata tokens (stack delta, etc.) are encoded
    in the structure of the 4-byte groups.
    """
    BYTE_RANGE = 256
    HALT = 256
    TRAP = 257
    OUTPUT = 258
    BRANCH_TAKEN = 259
    OPCODE_OFFSET = 260
    NOP = 518           # No-operation (for padding)
    SEP = 519           # Separator between program and trace
    VOCAB_SIZE = 520

    @staticmethod
    def encode_i32(val: int) -> list[int]:
        """Encode an i32 value as 4 byte tokens."""
        # Use unsigned pack to handle any int value
        b = struct.pack('<I', val & 0xFFFFFFFF)
        return [b[0], b[1], b[2], b[3]]

    @staticmethod
    def decode_i32(tokens: list[int]) -> int:
        """Decode 4 byte tokens to an i32 value."""
        b = bytes(tokens[:4])
        return struct.unpack('<i', b)[0]

    @staticmethod
    def encode_opcode(op: Op) -> int:
        """Encode an opcode as a token."""
        return op.value + TraceVocab.OPCODE_OFFSET


class TraceCompiler:
    """
    Compiles execution traces from the VM into token sequences
    that the transformer processes/generates.

    This bridges the gap between the VM's execution and the transformer's
    token-by-token generation.

    Trace format (from the blog):
        Each step produces tokens like:
        [byte0 byte1 byte2 byte3] commit(+delta, sts=sign, bt=branch)

        Where:
        - byte0-3: the i32 value on top of stack (little-endian)
        - delta: stack depth change
        - sts: stack top sign (whether result was pushed)
        - bt: whether a branch was taken

    Special tokens:
        - out(XX): output a value
        - halt: execution complete
        - branch_taken: branch was taken
    """

    def __init__(self):
        self.vocab = TraceVocab()

    def vm_trace_to_tokens(self, trace: list[dict]) -> list[int]:
        """
        Convert a VM execution trace to a sequence of tokens.

        Each trace entry becomes 4-5 tokens following the blog's format:
            [byte0 byte1 byte2 byte3] commit(delta, sts, bt)
        """
        tokens = []

        for entry in trace:
            op = entry.get("op", "")

            if op == "halt":
                tokens.append(TraceVocab.HALT)
                break

            if op == "trap":
                tokens.append(TraceVocab.TRAP)
                break

            # Encode stack top as 4 bytes
            val = entry.get("stack_top", 0) or 0
            tokens.extend(TraceVocab.encode_i32(val))

            # Encode commit metadata
            delta = entry.get("stack_delta", 0)
            bt = entry.get("branch_taken", False)

            if bt:
                tokens.append(TraceVocab.BRANCH_TAKEN)

            # Output marker
            if entry.get("output") is not None:
                tokens.append(TraceVocab.OUTPUT)
                tokens.extend(TraceVocab.encode_i32(entry["output"]))

        return tokens

    def tokens_to_text(self, tokens: list[int]) -> str:
        """
        Convert token sequence to human-readable text trace.
        Matches the blog's display format.
        """
        lines = []
        i = 0
        while i < len(tokens):
            if tokens[i] == TraceVocab.HALT:
                lines.append("halt")
                i += 1
            elif tokens[i] == TraceVocab.TRAP:
                lines.append("trap")
                i += 1
            elif tokens[i] == TraceVocab.BRANCH_TAKEN:
                lines.append("branch_taken")
                i += 1
            elif tokens[i] == TraceVocab.OUTPUT:
                i += 1
                if i + 4 <= len(tokens):
                    val = TraceVocab.decode_i32(tokens[i:i+4])
                    lines.append(f"out({val:02x}='{chr(val) if 32 <= val < 127 else '?'}')")
                    i += 4
                else:
                    lines.append("out(?)")
                    i = len(tokens)
            elif i + 4 <= len(tokens):
                # 4-byte value
                val = TraceVocab.decode_i32(tokens[i:i+4])
                b = tokens[i:i+4]
                lines.append(
                    f"{b[0]:02x} {b[1]:02x} {b[2]:02x} {b[3]:02x}"
                )
                i += 4
            else:
                i += 1

        return "\n".join(lines)

    def program_to_tokens(self, program: list[Instruction]) -> list[int]:
        """
        Encode a WASM program as input tokens.

        Format matches the blog:
        {
            opcode byte0 byte1 byte2 byte3
            ...
        }
        """
        tokens = []
        for inst in program:
            tokens.extend(inst.encode_tokens())
        return tokens
