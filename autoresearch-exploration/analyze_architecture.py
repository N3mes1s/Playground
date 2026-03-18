"""
Autoresearch Architecture Analyzer

CPU-safe introspection of the GPT model from karpathy/autoresearch.
Analyzes parameter counts, FLOP estimates, memory projections, and
layer-by-layer structure without requiring a GPU or training data.

Usage: python analyze_architecture.py [--depth DEPTH] [--aspect ASPECT]
"""

import argparse
import math
from dataclasses import dataclass, asdict


# ---------------------------------------------------------------------------
# Model config (mirrors train.py)
# ---------------------------------------------------------------------------

@dataclass
class GPTConfig:
    sequence_len: int = 2048
    vocab_size: int = 8192  # rustbpe default
    n_layer: int = 12
    n_head: int = 6
    n_kv_head: int = 6
    n_embd: int = 768
    window_pattern: str = "SSSL"


def has_ve(layer_idx, n_layer):
    """Returns True if layer should have Value Embedding (alternating, last always included)."""
    return layer_idx % 2 == (n_layer - 1) % 2


def build_config(depth, aspect_ratio=64, head_dim=128):
    """Build model config from depth and aspect ratio (mirrors train.py logic)."""
    base_dim = depth * aspect_ratio
    model_dim = ((base_dim + head_dim - 1) // head_dim) * head_dim
    num_heads = model_dim // head_dim
    return GPTConfig(
        n_layer=depth, n_head=num_heads, n_kv_head=num_heads, n_embd=model_dim,
    )


# ---------------------------------------------------------------------------
# Parameter counting (no torch needed)
# ---------------------------------------------------------------------------

def count_parameters(config):
    """Count parameters per component, matching train.py's GPT model."""
    d = config.n_embd
    V = config.vocab_size
    L = config.n_layer
    h = config.n_head
    kv_h = config.n_kv_head
    head_dim = d // h
    kv_dim = kv_h * head_dim

    # Token embedding
    wte = V * d

    # Per-layer attention: Q, K, V projections + output projection
    attn_per_layer = (
        d * (h * head_dim) +       # c_q
        d * (kv_h * head_dim) +    # c_k
        d * (kv_h * head_dim) +    # c_v
        d * d                       # c_proj (n_head * head_dim -> n_embd)
    )

    # Value embedding gate (32 -> n_kv_head, on alternating layers)
    ve_gate_channels = 32
    ve_gate_per_layer = ve_gate_channels * kv_h  # only on VE layers

    # MLP: up (d -> 4d) + down (4d -> d)
    mlp_per_layer = d * (4 * d) + (4 * d) * d

    # Count VE layers
    ve_layers = [i for i in range(L) if has_ve(i, L)]
    n_ve_layers = len(ve_layers)

    # Value embeddings: V * kv_dim per VE layer
    value_embeds = n_ve_layers * V * kv_dim

    # Per-layer scalars
    resid_lambdas = L
    x0_lambdas = L

    # LM head
    lm_head = d * V

    # Totals
    transformer_layers = L * (attn_per_layer + mlp_per_layer) + n_ve_layers * ve_gate_per_layer
    total = wte + transformer_layers + value_embeds + resid_lambdas + x0_lambdas + lm_head

    return {
        "wte": wte,
        "attn_per_layer": attn_per_layer,
        "mlp_per_layer": mlp_per_layer,
        "ve_gate_per_layer": ve_gate_per_layer,
        "transformer_layers_total": transformer_layers,
        "value_embeds": value_embeds,
        "n_ve_layers": n_ve_layers,
        "ve_layers": ve_layers,
        "resid_lambdas": resid_lambdas,
        "x0_lambdas": x0_lambdas,
        "lm_head": lm_head,
        "total": total,
    }


# ---------------------------------------------------------------------------
# FLOP estimation (mirrors train.py's estimate_flops)
# ---------------------------------------------------------------------------

def estimate_flops_per_token(config, params):
    """Estimated FLOPs per token (forward + backward ≈ 6× forward matmuls)."""
    nparams = params["total"]
    exclude = params["wte"] + params["value_embeds"] + params["resid_lambdas"] + params["x0_lambdas"]
    h = config.n_head
    q = config.n_embd // config.n_head
    t = config.sequence_len

    pattern = config.window_pattern.upper()
    long_window = config.sequence_len
    short_window = long_window // 2

    attn_flops = 0
    for layer_idx in range(config.n_layer):
        char = pattern[layer_idx % len(pattern)]
        window = long_window if char == "L" else short_window
        # Last layer always full attention
        if layer_idx == config.n_layer - 1:
            window = long_window
        effective_seq = min(window, t)
        attn_flops += 12 * h * q * effective_seq

    return 6 * (nparams - exclude) + attn_flops


# ---------------------------------------------------------------------------
# Memory estimation
# ---------------------------------------------------------------------------

def estimate_memory_gb(config, params, batch_size=128, dtype_bytes=2):
    """Rough estimate of peak GPU memory in GB."""
    # Model params (bf16)
    model_mem = params["total"] * dtype_bytes

    # Optimizer states: Muon needs momentum + second_momentum for matrix params,
    # AdamW needs exp_avg + exp_avg_sq for embedding params
    # Rough: ~2× model size for optimizer states
    optimizer_mem = params["total"] * dtype_bytes * 2

    # Activations (rough): batch_size × seq_len × n_embd × n_layer × dtype_bytes × ~3 (residual + attn + mlp)
    act_mem = batch_size * config.sequence_len * config.n_embd * config.n_layer * dtype_bytes * 3

    # Gradients: same as model
    grad_mem = params["total"] * dtype_bytes

    total = model_mem + optimizer_mem + act_mem + grad_mem
    return {
        "model_gb": model_mem / 1e9,
        "optimizer_gb": optimizer_mem / 1e9,
        "activations_gb": act_mem / 1e9,
        "gradients_gb": grad_mem / 1e9,
        "total_gb": total / 1e9,
    }


# ---------------------------------------------------------------------------
# Window pattern analysis
# ---------------------------------------------------------------------------

def analyze_window_pattern(config):
    """Analyze the sliding window attention pattern across layers."""
    pattern = config.window_pattern.upper()
    long_window = config.sequence_len
    short_window = long_window // 2

    layers = []
    for i in range(config.n_layer):
        char = pattern[i % len(pattern)]
        # Last layer always full
        if i == config.n_layer - 1:
            window = long_window
            wtype = "L (forced)"
        else:
            window = long_window if char == "L" else short_window
            wtype = char

        has_value_emb = has_ve(i, config.n_layer)
        layers.append({
            "layer": i,
            "window_type": wtype,
            "window_size": window,
            "has_ve": has_value_emb,
        })
    return layers


# ---------------------------------------------------------------------------
# Scaling analysis
# ---------------------------------------------------------------------------

def scaling_sweep(depths, aspect_ratio=64, head_dim=128):
    """Analyze how model scales with depth."""
    results = []
    for depth in depths:
        config = build_config(depth, aspect_ratio, head_dim)
        params = count_parameters(config)
        flops = estimate_flops_per_token(config, params)
        mem = estimate_memory_gb(config, params)
        results.append({
            "depth": depth,
            "dim": config.n_embd,
            "heads": config.n_head,
            "params_M": params["total"] / 1e6,
            "flops_per_token": flops,
            "est_memory_gb": mem["total_gb"],
        })
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyze autoresearch GPT architecture")
    parser.add_argument("--depth", type=int, default=8, help="Number of transformer layers (default: 8, train.py default)")
    parser.add_argument("--aspect", type=int, default=64, help="Aspect ratio: dim = depth * aspect (default: 64)")
    parser.add_argument("--head-dim", type=int, default=128, help="Head dimension (default: 128)")
    parser.add_argument("--sweep", action="store_true", help="Run scaling sweep across depths")
    args = parser.parse_args()

    print("=" * 70)
    print("AUTORESEARCH ARCHITECTURE ANALYSIS")
    print("=" * 70)

    config = build_config(args.depth, args.aspect, args.head_dim)
    print(f"\nModel Config:")
    for k, v in asdict(config).items():
        print(f"  {k:20s}: {v}")

    # Parameter counts
    params = count_parameters(config)
    print(f"\nParameter Counts:")
    print(f"  {'Token embedding (wte)':30s}: {params['wte']:>12,}")
    print(f"  {'Attention per layer':30s}: {params['attn_per_layer']:>12,}")
    print(f"  {'MLP per layer':30s}: {params['mlp_per_layer']:>12,}")
    print(f"  {'VE gate per layer':30s}: {params['ve_gate_per_layer']:>12,}")
    print(f"  {'Transformer layers total':30s}: {params['transformer_layers_total']:>12,}")
    print(f"  {'Value embeddings':30s}: {params['value_embeds']:>12,} ({params['n_ve_layers']} VE layers: {params['ve_layers']})")
    print(f"  {'Residual lambdas':30s}: {params['resid_lambdas']:>12,}")
    print(f"  {'x0 lambdas':30s}: {params['x0_lambdas']:>12,}")
    print(f"  {'LM head':30s}: {params['lm_head']:>12,}")
    print(f"  {'TOTAL':30s}: {params['total']:>12,} ({params['total']/1e6:.1f}M)")

    # FLOPs
    flops = estimate_flops_per_token(config, params)
    print(f"\nFLOPs per token (fwd+bwd): {flops:,.0f} ({flops/1e9:.2f} GFLOPs)")

    # Memory estimate
    mem = estimate_memory_gb(config, params)
    print(f"\nEstimated Memory (batch=128, bf16):")
    for k, v in mem.items():
        print(f"  {k:20s}: {v:.1f} GB")

    # Window pattern
    layers = analyze_window_pattern(config)
    print(f"\nLayer-by-Layer Structure:")
    print(f"  {'Layer':>5}  {'Window':>8}  {'Size':>6}  {'VE':>4}")
    print(f"  {'-'*5}  {'-'*8}  {'-'*6}  {'-'*4}")
    for l in layers:
        print(f"  {l['layer']:5d}  {l['window_type']:>8}  {l['window_size']:6d}  {'yes' if l['has_ve'] else 'no':>4}")

    # Scaling sweep
    if args.sweep:
        print(f"\n{'=' * 70}")
        print("SCALING SWEEP (aspect_ratio={}, head_dim={})".format(args.aspect, args.head_dim))
        print(f"{'=' * 70}")
        depths = [4, 6, 8, 10, 12, 16, 20, 24, 32]
        results = scaling_sweep(depths, args.aspect, args.head_dim)
        print(f"\n  {'Depth':>5}  {'Dim':>5}  {'Heads':>5}  {'Params(M)':>10}  {'GFLOPs/tok':>11}  {'Est Mem(GB)':>12}")
        print(f"  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*10}  {'-'*11}  {'-'*12}")
        for r in results:
            print(f"  {r['depth']:5d}  {r['dim']:5d}  {r['heads']:5d}  {r['params_M']:10.1f}  {r['flops_per_token']/1e9:11.2f}  {r['est_memory_gb']:12.1f}")

    # Interesting observations
    print(f"\n{'=' * 70}")
    print("KEY OBSERVATIONS")
    print(f"{'=' * 70}")
    print(f"""
1. RELU-SQUARED MLP: Uses F.relu(x).square() instead of GELU/SiLU.
   - Sparser activations (ReLU zeros + squaring amplifies non-zeros)
   - Computationally cheaper than GELU
   - No gating (unlike LLaMA's SwiGLU) — simpler, fewer params

2. VALUE EMBEDDINGS (ResFormer): Alternating layers get a separate
   V*kv_dim embedding table. The gate is input-dependent:
     gate = 2 * sigmoid(W_gate @ x[:32])  # only first 32 channels
     v = v + gate * ve
   This costs {params['value_embeds']:,} params ({params['value_embeds']/params['total']*100:.1f}% of model).

3. MUON OPTIMIZER: Polar-express orthogonalization for matrix params
   (Newton-Schulz iterations), with NorMuon variance reduction.
   AdamW only used for embeddings and per-layer scalars.
   Separate LR groups: embedding=0.6, unembedding=0.004, matrix=0.04, scalar=0.5

4. SLIDING WINDOW (SSSL): 3 short-context + 1 long-context layers.
   Short = seq_len/2 = {config.sequence_len//2}, Long = seq_len = {config.sequence_len}.
   Last layer always forced to full attention.
   Saves ~25% attention FLOPs vs all-full.

5. RESIDUAL STRUCTURE: x = λ_resid[i] * x + λ_x0[i] * x0
   Init: λ_resid=1.0, λ_x0=0.1 → mild skip connection to input embedding.
   Learned per-layer. This is a simplified version of DenseFormer.

6. LOGIT SOFTCAP: 15 * tanh(logits / 15) prevents extreme logits.
   Used in Gemma 2 / PaLM 2. Helps training stability.

7. TIME-BASED SCHEDULING: LR schedule is based on wall-clock progress
   (training_time / 300s), not step count. This means the schedule
   adapts automatically when architecture changes affect throughput.
""")


if __name__ == "__main__":
    main()
