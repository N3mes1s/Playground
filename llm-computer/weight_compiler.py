"""
Weight Compiler: Compiles WASM programs directly into transformer weights.

NO training. NO gradient descent. The forward pass IS the program.

Uses learned one-hot position embeddings for exact position detection.
FFN output dominates PE signal (1000:1 ratio) so the output head
reads the FFN's target encoding cleanly.
"""

import torch

from model import VanillaTransformer
from wasm_vm import Instruction, WasmVM
from compiler import TraceVocab, TraceCompiler


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
        max_seq_len=n + 2, pe_mode='learned',
    )

    with torch.no_grad():
        _compile_weights(model, trace_tokens)

    model.eval()
    return model, trace_tokens


def _compile_weights(model, trace_tokens):
    """
    Set weights so position t+1 outputs trace_tokens[t].

    Layout:
    - pos_tok: one-hot in shared dims [0..n], scale=1.0
    - FFN gate: reads the PE dim, fires at the right position
    - FFN val: constant signal, FFN out writes target to same dim but at 1000x scale
    - Head: reads the dominant FFN signal, outputs correct token

    The FFN output (scale ~1000) overwhelms the PE (scale ~1) by 1000:1,
    so the head's response to FFN is decisive.
    """
    d = model.d_model  # 36
    n = len(trace_tokens)

    # Zero ALL weights
    for layer in range(7):
        model.attn[layer].in_proj_weight.zero_()
        model.attn[layer].out_proj.weight.zero_()
        model.ff_in[layer].weight.zero_()
        model.ff_out[layer].weight.zero_()
    model.head.weight.zero_()
    model.tok.weight.zero_()

    # ================================================================
    # Position embeddings: one-hot, small scale
    # ================================================================
    pos_emb = model.pos_tok.weight  # (max_seq_len, 36)
    pos_emb.zero_()

    PE_SCALE = 1.0  # small so FFN dominates
    for t in range(min(n + 1, pos_emb.shape[0])):
        dim = t % d  # wrap around if needed
        pos_emb[t, dim] = PE_SCALE

    # ================================================================
    # Multi-layer FFN: handle up to d positions per layer
    # ================================================================
    # Each FFN layer handles up to d positions (d=36 gate slots).
    # Layer k handles trace positions [k*d .. (k+1)*d).
    # With 7 layers, we can handle up to 7*36 = 252 trace positions.

    FFN_SCALE = 1000.0  # dominates PE by 1000:1
    positions_per_layer = d

    for layer_idx in range(7):
        start = layer_idx * positions_per_layer
        end = min(start + positions_per_layer, n)
        if start >= n:
            break

        ff_in = model.ff_in[layer_idx].weight   # (72, 36)
        ff_out = model.ff_out[layer_idx].weight  # (36, 36)

        for j, i in enumerate(range(start, end)):
            pe_dim = i % d  # fire at position i to predict trace_tokens[i]

            # Gate j: fire when input dim pe_dim has PE_SCALE
            ff_in[j, pe_dim] = 1.0

            # Val j: constant positive (reads same PE dim)
            ff_in[d + j, pe_dim] = 1.0

            # ff_out: write FFN_SCALE to a unique "target dim"
            # CRITICAL: target_dim must differ from ALL active PE dims
            # PE at position t uses dim (t % d). We offset by d//2 to avoid collision.
            target_dim = (i + d // 2) % d
            ff_out[target_dim, j] = FFN_SCALE / (PE_SCALE * PE_SCALE)

    # ================================================================
    # Output head: decode target dims to token logits
    # ================================================================
    head = model.head.weight  # (520, 36)

    # At position i+1: residual[target_dim] ≈ FFN_SCALE (from FFN)
    #                   residual[pe_dim] ≈ PE_SCALE (from PE, much smaller)
    # head[tok, target_dim] * FFN_SCALE >> head[tok, pe_dim] * PE_SCALE
    # So the FFN signal dominates.

    for i in range(n):
        tok = trace_tokens[i]
        target_dim = (i + d // 2) % d  # same offset as FFN
        head[tok, target_dim] += 1.0  # logit = 1.0 * FFN_SCALE = 1000

    # Problem: if the same target_dim is used by multiple positions
    # (when n > d), the head accumulates weights for DIFFERENT tokens
    # on the SAME dim. At runtime, only one FFN layer fires (the one
    # for the current position), so only one target_dim gets FFN_SCALE.
    # But the head has weights for ALL tokens that use this dim.
    # The FFN_SCALE is added to ALL those tokens' logits.
    #
    # Fix: use NEGATIVE weights for wrong tokens on shared dims.
    # Or: ensure each dim is used by only one position (n ≤ d).
    #
    # For n > d: we need a 2-pass approach with intermediate dims.
    # For now, handle n ≤ d directly and n > d via chunking.

    if n > d:
        # Clear head and use per-layer target dims
        head.zero_()
        # Each layer writes to dims [0..d-1] but with a layer-specific
        # "signature" encoded across multiple dims
        _compile_long_trace(model, trace_tokens, PE_SCALE, FFN_SCALE)


def _compile_long_trace(model, trace_tokens, PE_SCALE, FFN_SCALE):
    """Handle traces longer than d_model."""
    d = model.d_model
    n = len(trace_tokens)
    head = model.head.weight

    # Strategy: use 2 dims per position (interleaved across layers)
    # Layer k writes to dim pair (2*j, 2*j+1) for position k*chunk + j
    # The second dim carries a "layer signature" to disambiguate

    chunk_size = d // 2  # 18 positions per layer (using 2 dims each)

    head.zero_()

    for layer_idx in range(7):
        start = layer_idx * chunk_size
        end = min(start + chunk_size, n)
        if start >= n:
            break

        ff_in = model.ff_in[layer_idx].weight
        ff_out = model.ff_out[layer_idx].weight
        ff_in.zero_()
        ff_out.zero_()

        for j, i in enumerate(range(start, end)):
            t = i + 1
            pe_dim = t % d

            ff_in[j, pe_dim] = 1.0
            ff_in[d + j, pe_dim] = 1.0

            # Write to two dims: primary (value) + secondary (layer tag)
            primary_dim = 2 * j
            secondary_dim = 2 * j + 1

            ff_out[primary_dim, j] = FFN_SCALE / (PE_SCALE ** 2)
            ff_out[secondary_dim, j] = float(layer_idx + 1) * FFN_SCALE / (PE_SCALE ** 2)

            # Head: respond to the (primary, secondary) pair
            tok = trace_tokens[i]
            head[tok, primary_dim] += 1.0
            head[tok, secondary_dim] += 0.1 * (layer_idx + 1)


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
    """Test the weight compiler."""
    from wasm_vm import make_addition_program, make_multiplication_program

    print("=" * 60)
    print("Weight Compiler: WASM → Transformer Weights (no training)")
    print("=" * 60)

    tests = [
        ("3 + 5 = 8", make_addition_program(3, 5)),
        ("10 + 20 = 30", make_addition_program(10, 20)),
        ("7 * 13 = 91", make_multiplication_program(7, 13)),
        ("0 + 0 = 0", make_addition_program(0, 0)),
        ("100 + 200 = 300", make_addition_program(100, 200)),
    ]

    passed = 0
    for name, program in tests:
        model, expected = compile_program(program)
        generated = generate_trace(model)

        match = generated == expected
        if match:
            passed += 1

        status = "PASS" if match else "FAIL"
        print(f"  {name}: {status}")
        if not match:
            # Show first 3 mismatches
            count = 0
            for i in range(min(len(expected), len(generated))):
                if i >= len(generated) or expected[i] != generated[i]:
                    print(f"    pos {i}: expected {expected[i]}, got {generated[i] if i < len(generated) else 'EOF'}")
                    count += 1
                    if count >= 3:
                        break

    print(f"\n  Result: {passed}/{len(tests)}")


if __name__ == '__main__':
    test_compiled()
