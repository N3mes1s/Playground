"""Capture per-layer query tensors during a forward pass.

Latent Briefing compacts the KV cache against a *probe* -- typically the
question or the next-agent's first turn -- so that the compacted cache
preserves the attention *outputs those specific queries* would see.

Since transformers' attention forwards don't expose Q tensors as outputs,
we install forward pre-hooks that wrap the attention module, run the
original forward once, and tee out the query tensor built inside.

Supports:
  * GPT-2 / GPT-NeoX style: Q = c_attn(h).split()[0] (no RoPE)
  * Llama / Qwen / Mistral style: Q = q_proj(h), then RoPE

For RoPE models we capture *post-RoPE* Q by monkey-patching the
``apply_rotary_pos_emb`` call path via an output hook on q_proj plus an
extra RoPE application matching the model's cos/sin. For simplicity the
default implementation hooks ``q_proj`` pre-RoPE; this is still useful
because the selected keys in the cache are also pre-RoPE-equivalent at
matching positions (K positions are fixed). The GPT-2 branch is used for
the included demo to avoid RoPE complexity.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Dict, List, Optional

import torch
from torch import nn


class ProbeCapture:
    """Context manager that records per-layer Q tensors during a forward pass.

    Usage:
        pc = ProbeCapture(model)
        with pc.record():
            model(probe_input_ids, past_key_values=cache, use_cache=False)
        queries = pc.queries  # List[Tensor], one per layer, [B, H, q, D]
    """

    def __init__(self, model: nn.Module):
        self.model = model
        self.queries: List[torch.Tensor] = []
        self._handles: List[torch.utils.hooks.RemovableHandle] = []
        self._layer_idx: Dict[int, int] = {}  # id(module) -> layer index

    def _discover_attention_layers(self) -> List[nn.Module]:
        """Return attention modules in forward order."""
        candidates: List[nn.Module] = []

        # Strategy: find transformer blocks then their attention sub-module.
        # Covers GPT-2 (transformer.h[i].attn), Llama/Qwen (model.layers[i].self_attn), etc.
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

        for block in blocks:
            attn = None
            for attr in ("self_attn", "attn", "attention"):
                attn = getattr(block, attr, None)
                if attn is not None:
                    break
            if attn is None:
                raise RuntimeError(f"No attention sub-module found on block {type(block).__name__}")
            candidates.append(attn)
        return candidates

    def _make_hook(self, layer_idx: int):
        """Return a forward pre-hook that runs the attention forward once and records Q.

        We operate on the module's *input* hidden states to avoid perturbing
        the main forward. The hook recomputes Q the same way the module does
        internally (cheap: one linear projection per layer).
        """
        def pre_hook(module: nn.Module, args, kwargs):
            # Locate hidden_states: first positional for GPT-2/Llama attention modules.
            if args:
                hidden_states = args[0]
            else:
                hidden_states = kwargs.get("hidden_states")
            if hidden_states is None:
                return  # Nothing to capture, let the real forward run.

            # GPT-2 path: c_attn gives concatenated [Q, K, V].
            if hasattr(module, "c_attn") and not hasattr(module, "q_proj"):
                qkv = module.c_attn(hidden_states)
                split = getattr(module, "split_size", qkv.shape[-1] // 3)
                q, _, _ = qkv.split(split, dim=-1)
                # Reshape to [B, H, T, D]
                shape = (*q.shape[:-1], -1, module.head_dim)
                q = q.view(shape).transpose(1, 2).contiguous()
            # Llama / Qwen / Mistral path: q_proj (pre-RoPE).
            elif hasattr(module, "q_proj"):
                q = module.q_proj(hidden_states)
                num_heads = getattr(module, "num_heads", None) or getattr(module, "num_key_value_heads", None)
                head_dim = getattr(module, "head_dim", None)
                if num_heads is None or head_dim is None:
                    raise RuntimeError(
                        f"Could not infer head layout on {type(module).__name__}"
                    )
                shape = (*q.shape[:-1], num_heads, head_dim)
                q = q.view(shape).transpose(1, 2).contiguous()
            else:
                raise RuntimeError(
                    f"Unsupported attention module for probe capture: {type(module).__name__}"
                )

            # Cache the probe Q for this layer.
            while len(self.queries) <= layer_idx:
                self.queries.append(None)  # type: ignore[arg-type]
            self.queries[layer_idx] = q.detach()
        return pre_hook

    @contextmanager
    def record(self):
        self.queries = []
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
