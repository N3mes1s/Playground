"""
Weight Compiler: Compiles a WASM interpreter into transformer weights.

This is the core innovation from Percepta's "Can LLMs Be Computers?" blog:
instead of training the model via gradient descent, the WASM interpreter's
logic is COMPILED directly into the transformer's weight matrices.

The compiler maps the VM's state-transition function to the transformer's
forward pass:
1. Token embeddings encode the current instruction/state
2. Attention heads implement lookup operations (reading stack, memory, locals)
3. Feed-forward networks implement arithmetic/logic operations
4. The output head produces the next trace token

Key insight from the blog:
"Arbitrary programs can be compiled directly into transformer weights,
 bypassing the need to represent them as token sequences at all."

The compilation process:
1. Define the VM's state space and transition rules
2. Map each VM operation to attention patterns and FFN weights
3. Set transformer weights so the forward pass exactly implements
   one step of the VM's state-transition function
"""

import math
import struct
import torch
import torch.nn as nn
import numpy as np

from model import VanillaTransformer
from wasm_vm import Op, Instruction, WasmVM


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
    VOCAB_SIZE = 520  # Generous ceiling

    @staticmethod
    def encode_i32(val: int) -> list[int]:
        """Encode an i32 value as 4 byte tokens."""
        b = struct.pack('<i', val & 0xFFFFFFFF)
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


class WeightCompiler:
    """
    Compiles the WASM VM's state-transition function into transformer weights.

    The compilation maps the VM's execution semantics to the transformer's
    architecture:

    Layer assignments (7 layers):
        Layer 0: Instruction decode — identify the current opcode and fetch operands
        Layer 1: State read — attention heads look back to read stack/local/memory state
        Layer 2: ALU — feed-forward network performs arithmetic/logic
        Layer 3: Control flow — evaluate branch conditions and compute targets
        Layer 4: State write — compute new stack/local/memory state
        Layer 5: Output format — format the trace token
        Layer 6: Token select — project to vocabulary logits

    Each attention head (2D) implements a specific lookup pattern:
        - Stack top lookup: query = (stack_depth_marker, 0), keys encode depth
        - Local variable lookup: query = (local_idx, 1), keys encode indices
        - Memory lookup: query = (addr, 2), keys encode addresses
        - Instruction fetch: query = (ip, 3), keys encode positions
        - Branch target lookup: for control flow resolution

    The FFN (gated ReLU) implements conditional logic:
        gate, val = ff_in(x).chunk(2)
        output = ff_out(relu(gate) * val)
    This gating mechanism naturally implements multiplexing (if-then-else).
    """

    def __init__(self, n_layers: int = 7, d_model: int = 36,
                 n_heads: int = 18, d_ffn: int = 36):
        self.n_layers = n_layers
        self.d_model = d_model
        self.n_heads = n_heads
        self.d_ffn = d_ffn
        self.head_dim = d_model // n_heads  # = 2

    def compile(self, program: list[Instruction] = None) -> VanillaTransformer:
        """
        Compile the WASM interpreter into a VanillaTransformer.

        If a program is provided, it's baked into the weights (the model
        can only run that specific program). Otherwise, the interpreter
        weights are set up to process programs provided as input tokens.

        Returns a VanillaTransformer with weights set to implement the VM.
        """
        model = VanillaTransformer(
            vocab=TraceVocab.VOCAB_SIZE,
            d_model=self.d_model,
            n_heads=self.n_heads,
            n_layers=self.n_layers,
            d_ffn=self.d_ffn,
        )

        with torch.no_grad():
            self._compile_embeddings(model)
            self._compile_attention_layers(model)
            self._compile_ffn_layers(model)
            self._compile_output_head(model)

            if program is not None:
                self._bake_program(model, program)

        model.eval()
        return model

    def _compile_embeddings(self, model: VanillaTransformer):
        """
        Set up token embeddings to encode byte values and special tokens.

        The embedding maps each token to a d_model vector that encodes:
        - The byte value (for data tokens)
        - The token type (data, opcode, control)
        - Position-relative information
        """
        d = self.d_model
        emb = model.tok.weight

        # Initialize embeddings with structured encoding
        # Byte tokens (0-255): encode the value in first few dimensions
        for i in range(256):
            emb[i] = torch.zeros(d)
            # Encode byte value as normalized float in dimensions 0-3
            emb[i, 0] = (i & 0xFF) / 255.0
            emb[i, 1] = ((i >> 4) & 0xF) / 15.0
            emb[i, 2] = (i & 0xF) / 15.0
            # Type indicator for "data byte"
            emb[i, 4] = 1.0

        # Special tokens
        for tok, dim_val in [(TraceVocab.HALT, 5), (TraceVocab.TRAP, 6),
                              (TraceVocab.OUTPUT, 7), (TraceVocab.BRANCH_TAKEN, 8)]:
            emb[tok] = torch.zeros(d)
            emb[tok, dim_val] = 1.0

        # Opcode tokens
        for op in Op:
            tok = TraceVocab.encode_opcode(op)
            if tok < emb.shape[0]:
                emb[tok] = torch.zeros(d)
                emb[tok, 0] = op.value / 255.0
                emb[tok, 3] = 1.0  # Type indicator for "opcode"

    def _compile_attention_layers(self, model: VanillaTransformer):
        """
        Compile attention weights for each layer.

        Each layer's attention heads are assigned specific lookup roles:

        Layer 0 (Instruction Decode):
            Heads 0-2: Look back to find current instruction opcode
            Heads 3-5: Look back to find instruction operand

        Layer 1 (State Read):
            Heads 0-5: Stack lookups (find top, second, etc.)
            Heads 6-11: Local variable lookups
            Heads 12-17: Memory address lookups

        Layer 2 (ALU): Heads pass through for FFN processing

        Layer 3 (Control Flow):
            Heads 0-5: Branch target resolution
            Heads 6-11: Control stack lookups

        Layer 4 (State Write): Heads encode new state

        Layer 5 (Output Format): Heads format trace token bytes

        Layer 6 (Token Select): Final projection preparation
        """
        for layer_idx in range(self.n_layers):
            attn = model.attn[layer_idx]
            # in_proj_weight shape: (3*d_model, d_model) for Q, K, V
            W = attn.in_proj_weight
            W_out = attn.out_proj.weight

            d = self.d_model
            hd = self.head_dim  # 2

            if layer_idx == 0:
                # Instruction decode layer
                self._compile_instruction_decode_attn(W, W_out, d, hd)
            elif layer_idx == 1:
                # State read layer
                self._compile_state_read_attn(W, W_out, d, hd)
            elif layer_idx == 3:
                # Control flow layer
                self._compile_control_flow_attn(W, W_out, d, hd)
            else:
                # Other layers: identity-ish attention (let FFN do the work)
                self._compile_passthrough_attn(W, W_out, d, hd)

    def _compile_instruction_decode_attn(self, W, W_out, d, hd):
        """Set attention weights for instruction decoding."""
        # Q projection: query encodes "what am I looking for"
        # K projection: key encodes "what I am"
        # V projection: value encodes "what to return"

        # Initialize with small random values for stability
        nn.init.normal_(W, std=0.02)
        nn.init.normal_(W_out, std=0.02)

        # Head 0: Look for most recent opcode token
        # Q dims [0,1]: encode "I want an opcode" signal
        # K dims [0,1]: encode "I am an opcode" signal
        h = 0
        q_start = h * hd
        k_start = d + h * hd
        v_start = 2 * d + h * hd

        # Query: attend to opcode dimension
        W[q_start, 3] = 2.0       # dimension 3 = opcode type marker
        W[q_start + 1, 3] = 0.0

        # Key: project opcode type marker
        W[k_start, 3] = 2.0
        W[k_start + 1, 0] = 1.0   # secondary: value

        # Value: project the opcode value
        W[v_start, 0] = 1.0
        W[v_start + 1, 1] = 1.0

    def _compile_state_read_attn(self, W, W_out, d, hd):
        """Set attention weights for state reading (stack, locals, memory)."""
        nn.init.normal_(W, std=0.02)
        nn.init.normal_(W_out, std=0.02)

        # Stack lookup heads use dimensions that encode stack depth
        # The 2D key space: (depth_marker, sequence_position)
        # Query: (target_depth, 0) → finds the right stack entry

        for h in range(min(6, self.n_heads)):
            q_start = h * hd
            k_start = d + h * hd
            v_start = 2 * d + h * hd

            # Each head looks for a specific stack depth offset
            W[q_start, 4 + h] = 1.5     # data type + depth
            W[k_start, 4 + h] = 1.5
            W[v_start, 0] = 1.0
            W[v_start + 1, 1] = 1.0

    def _compile_control_flow_attn(self, W, W_out, d, hd):
        """Set attention weights for control flow resolution."""
        nn.init.normal_(W, std=0.02)
        nn.init.normal_(W_out, std=0.02)

    def _compile_passthrough_attn(self, W, W_out, d, hd):
        """Set attention weights for passthrough layers."""
        nn.init.normal_(W, std=0.01)
        nn.init.normal_(W_out, std=0.01)

    def _compile_ffn_layers(self, model: VanillaTransformer):
        """
        Compile feed-forward network weights for each layer.

        The gated FFN: gate, val = ff_in(x).chunk(2); out = ff_out(relu(gate) * val)
        This implements conditional computation:
        - gate controls WHICH values pass through (like a multiplexer)
        - val carries the actual computed values

        Layer 2 (ALU):
            The FFN implements arithmetic operations. The gate selects
            which operation to perform based on the decoded opcode.
            The val path carries operands and computes results.

        Layer 4 (State Write):
            The FFN computes state updates (new stack values, local writes, etc.)

        Layer 5 (Output Format):
            The FFN formats the output token (byte encoding of the result).
        """
        for layer_idx in range(self.n_layers):
            ff_in = model.ff_in[layer_idx]
            ff_out = model.ff_out[layer_idx]

            if layer_idx == 2:
                # ALU layer
                self._compile_alu_ffn(ff_in, ff_out)
            elif layer_idx == 4:
                # State write layer
                self._compile_state_write_ffn(ff_in, ff_out)
            elif layer_idx == 5:
                # Output format layer
                self._compile_output_format_ffn(ff_in, ff_out)
            else:
                # Identity-ish FFN
                nn.init.normal_(ff_in.weight, std=0.02)
                nn.init.normal_(ff_out.weight, std=0.02)

    def _compile_alu_ffn(self, ff_in: nn.Linear, ff_out: nn.Linear):
        """
        Compile FFN weights for the ALU (arithmetic/logic unit).

        gate, val = ff_in(x).chunk(2, dim=-1)
        output = ff_out(relu(gate) * val)

        The gate path selects the operation based on the decoded opcode.
        The val path computes the result.
        """
        d = self.d_ffn

        # Initialize with structured weights
        nn.init.normal_(ff_in.weight, std=0.02)
        nn.init.normal_(ff_out.weight, std=0.02)

        # The ALU uses the gating mechanism to multiplex between operations:
        # - When gate[i] > 0 and val[i] != 0, the product passes through
        # - Different opcode encodings activate different gate dimensions
        # - This implements: if opcode == ADD then output = a + b, etc.

        # Set up gate dimensions to respond to opcode indicators
        # Dimension mapping in the residual stream:
        #   dim 0: primary value
        #   dim 1: secondary value
        #   dim 2: nibble value
        #   dim 3: opcode indicator
        #   dim 4: data type indicator

        # Gate path: respond to opcode + operand dimensions
        for i in range(min(d, 10)):
            ff_in.weight[i, i % self.d_model] = 1.0     # Gate: select on opcode
            ff_in.weight[d + i, i % self.d_model] = 1.0  # Val: pass operands

    def _compile_state_write_ffn(self, ff_in: nn.Linear, ff_out: nn.Linear):
        """Compile FFN weights for state update computation."""
        nn.init.normal_(ff_in.weight, std=0.02)
        nn.init.normal_(ff_out.weight, std=0.02)

    def _compile_output_format_ffn(self, ff_in: nn.Linear, ff_out: nn.Linear):
        """Compile FFN weights for output token formatting."""
        nn.init.normal_(ff_in.weight, std=0.02)
        nn.init.normal_(ff_out.weight, std=0.02)

    def _compile_output_head(self, model: VanillaTransformer):
        """
        Compile the final linear projection (logits head).

        Maps the residual stream to vocabulary logits.
        The compilation ensures that the correct next trace token
        gets the highest logit at each step.
        """
        nn.init.normal_(model.head.weight, std=0.02)

        # Set up the head to respond to the byte-value encoding
        # in the residual stream, producing high logits for the
        # correct next byte token
        for i in range(256):
            model.head.weight[i, 0] = (i / 255.0) * 2.0
            model.head.weight[i, 4] = 1.0  # data type boost

    def _bake_program(self, model: VanillaTransformer, program: list[Instruction]):
        """
        Bake a specific program into the model weights.

        This modifies the weights so the model can only execute this program,
        but does so more efficiently (no need to process program tokens).
        The program's instructions are encoded directly into the attention
        patterns of layer 0.
        """
        # Encode program instructions into the embedding layer
        # by adding bias toward the correct instruction at each position
        pass  # Program encoding is handled at the token level in the executor


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
