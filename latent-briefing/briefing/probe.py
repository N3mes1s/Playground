"""Capture per-layer query tensors during a forward pass.

Latent Briefing compacts the KV cache against a *probe* -- typically the
worker's task/question -- so the compacted cache preserves the attention
outputs those queries would see. We need the per-layer post-RoPE Q
(matching the post-RoPE K stored in the cache) -- capturing pre-RoPE Q
would compute meaningless dot products against RoPE'd keys.

The module installs forward pre-hooks on each attention module. When the
probe forward runs the hook:
  1. Reads ``hidden_states`` from the call args.
  2. Runs ``q_proj`` (or GPT-2's ``c_attn`` split) to get the raw Q.
  3. For RoPE models, applies the model's own ``apply_rotary_pos_emb``
     using the ``position_embeddings=(cos, sin)`` already passed into the
     attention forward by the parent block.
  4. Stores the result, shaped ``[B, H, q, D]``.

The pre-hook is side-effect-free on the main forward: we only read
inputs and recompute Q, leaving the real forward to proceed normally.
"""
from __future__ import annotations

import importlib
from contextlib import contextmanager
from typing import Dict, List, Optional

import torch
from torch import nn


def _locate_apply_rotary(module: nn.Module):
    """Return the architecture-local ``apply_rotary_pos_emb`` function, or None.

    Looks up the module's class's source module and checks for an
    ``apply_rotary_pos_emb`` symbol. Works for Llama, Qwen, Qwen2, Qwen3,
    Mistral, Gemma, Gemma2, Phi, etc. -- all of which expose the function
    at module scope in transformers 4.x / 5.x.
    """
    mod_name = type(module).__module__
    try:
        mod = importlib.import_module(mod_name)
    except ImportError:
        return None
    return getattr(mod, "apply_rotary_pos_emb", None)


class ProbeCapture:
    """Context manager that records per-layer Q tensors during a forward pass.

    Usage:
        pc = ProbeCapture(model)
        with pc.record():
            model(probe_input_ids, past_key_values=cache, use_cache=True)
        queries = pc.queries  # List[Tensor], one per layer, shape [B, H, q, D]

    Tensor conventions:
      * GPT-2 / GPT-NeoX: ``H`` = num_attention_heads (no KV grouping).
      * Llama-family:    ``H`` = num_attention_heads (full query heads,
                         post-RoPE). Use ``align_probe_to_kv_heads()`` to
                         reduce to num_kv_heads before AM.
    """

    def __init__(self, model: nn.Module):
        self.model = model
        self.queries: List[torch.Tensor] = []
        self.used_rope: List[bool] = []  # per-layer flag; True if Q is post-RoPE
        self._handles: List[torch.utils.hooks.RemovableHandle] = []

    def _discover_attention_layers(self) -> List[nn.Module]:
        roots = []
        for attr in ("transformer", "model", "gpt_neox", "base_model"):
            sub = getattr(self.model, attr, None)
            if sub is not None:
                roots.append(sub)
        roots.append(self.model)

        blocks = None
        for root in roots:
            for attr in ("h", "layers", "blocks"):
                maybe = getattr(root, attr, None)
                if isinstance(maybe, (nn.ModuleList, list)) and len(maybe) > 0:
                    blocks = maybe
                    break
            if blocks is not None:
                break

        if blocks is None:
            raise RuntimeError(
                "Could not locate transformer block list on model; "
                "unsupported architecture."
            )

        attn_modules: List[nn.Module] = []
        for block in blocks:
            attn = None
            for attr in ("self_attn", "attn", "attention"):
                attn = getattr(block, attr, None)
                if attn is not None:
                    break
            if attn is None:
                raise RuntimeError(
                    f"No attention sub-module found on block {type(block).__name__}"
                )
            attn_modules.append(attn)
        return attn_modules

    def _make_hook(self, layer_idx: int):
        def pre_hook(module: nn.Module, args, kwargs):
            # Extract hidden_states regardless of positional/keyword form.
            hidden_states = args[0] if args else kwargs.get("hidden_states")
            if hidden_states is None:
                return

            # --- GPT-2 path: c_attn gives concatenated [Q, K, V], no RoPE ---
            if hasattr(module, "c_attn") and not hasattr(module, "q_proj"):
                qkv = module.c_attn(hidden_states)
                split = getattr(module, "split_size", qkv.shape[-1] // 3)
                q, _, _ = qkv.split(split, dim=-1)
                head_dim = module.head_dim
                shape = (*q.shape[:-1], -1, head_dim)
                q = q.view(shape).transpose(1, 2).contiguous()
                used_rope = False

            # --- Llama/Qwen/Mistral/Gemma/Phi path: q_proj then RoPE ---
            elif hasattr(module, "q_proj"):
                head_dim = getattr(module, "head_dim", None)
                if head_dim is None:
                    cfg = getattr(module, "config", None)
                    head_dim = getattr(cfg, "head_dim", None) if cfg else None
                if head_dim is None:
                    raise RuntimeError(
                        f"Could not determine head_dim on {type(module).__name__}"
                    )

                q = module.q_proj(hidden_states)
                input_shape = hidden_states.shape[:-1]
                q = q.view(*input_shape, -1, head_dim).transpose(1, 2).contiguous()

                # Locate position_embeddings=(cos, sin) passed to the block.
                position_embeddings = None
                # In modern transformers, this is always a kwarg from the decoder block.
                if "position_embeddings" in kwargs:
                    position_embeddings = kwargs["position_embeddings"]
                elif len(args) >= 2 and isinstance(args[1], tuple):
                    position_embeddings = args[1]

                used_rope = False
                if position_embeddings is not None:
                    apply_rope = _locate_apply_rotary(module)
                    if apply_rope is None:
                        raise RuntimeError(
                            f"Architecture {type(module).__name__} provides "
                            f"position_embeddings but no apply_rotary_pos_emb "
                            f"in module {type(module).__module__}. Probe would "
                            f"produce meaningless pre-RoPE Q."
                        )
                    cos, sin = position_embeddings
                    # apply_rotary_pos_emb takes (q, k, cos, sin) and returns both.
                    # We pass q as both to avoid allocating a separate dummy.
                    try:
                        q_rope, _ = apply_rope(q, q, cos, sin)
                    except Exception as exc:
                        raise RuntimeError(
                            f"apply_rotary_pos_emb failed on "
                            f"{type(module).__name__}; probe cannot be made "
                            f"post-RoPE. Upstream error: {exc!r}"
                        ) from exc
                    q = q_rope.contiguous()
                    used_rope = True
                # If position_embeddings was None, either (a) the architecture
                # has no RoPE (unlikely for a q_proj-style module) or (b) the
                # model called attention without it. Keep pre-RoPE Q; caller
                # can check used_rope to decide whether to trust the probe.
            else:
                raise RuntimeError(
                    f"Unsupported attention module for probe capture: {type(module).__name__}"
                )

            while len(self.queries) <= layer_idx:
                self.queries.append(None)  # type: ignore[arg-type]
                self.used_rope.append(False)
            self.queries[layer_idx] = q.detach()
            self.used_rope[layer_idx] = used_rope
        return pre_hook

    @contextmanager
    def record(self):
        self.queries = []
        self.used_rope = []
        self._handles = []
        for idx, attn in enumerate(self._discover_attention_layers()):
            self._handles.append(
                attn.register_forward_pre_hook(self._make_hook(idx), with_kwargs=True)
            )
        try:
            yield self
        finally:
            for h in self._handles:
                h.remove()
            self._handles = []

    def rope_summary(self) -> Dict[str, int]:
        """Return {'total': N, 'with_rope': K} describing probe correctness."""
        return {
            "total": len(self.queries),
            "with_rope": sum(1 for f in self.used_rope if f),
        }


def align_probe_to_kv_heads(
    q_probe: torch.Tensor,
    num_kv_heads: int,
) -> torch.Tensor:
    """Reduce query-head count to KV-head count for GQA/MQA models.

    Mean-pools heads within each KV group so the probe has one Q per KV head.
    For non-GQA models (num_heads == num_kv_heads) this is a no-op.
    """
    b, h, q, d = q_probe.shape
    if h == num_kv_heads:
        return q_probe
    if h % num_kv_heads != 0:
        raise ValueError(f"num_heads {h} not divisible by num_kv_heads {num_kv_heads}")
    group = h // num_kv_heads
    return q_probe.view(b, num_kv_heads, group, q, d).mean(dim=2)
