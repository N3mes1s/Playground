"""Helpers for compacting Hugging Face ``DynamicCache`` objects.

Transformers' modern cache holds per-layer K/V as tensors of shape
``[batch, num_kv_heads, seq_len, head_dim]``. Latent Briefing compacts each
layer independently with its own probe queries and writes the result back
into a fresh cache.

This module hides the version drift across transformers releases: older
versions expose ``past_key_values`` as a tuple of ``(k, v)`` per layer,
newer ones use the ``DynamicCache`` class. We normalise to a list of
``(k, v)`` pairs, compact, then rebuild a cache of the same type.
"""
from __future__ import annotations

from typing import Callable, List, Optional, Sequence, Tuple

import torch

from .attention_matching import CompactionResult, attention_match


# Normalised representation: List[ Tuple[k, v] ] where k, v are
# [batch, num_kv_heads, seq_len, head_dim].
CachePair = Tuple[torch.Tensor, torch.Tensor]


def _cache_to_pairs(cache) -> List[CachePair]:
    if cache is None:
        return []
    # transformers >= 4.50: DynamicCache.layers[i].{keys,values}
    if hasattr(cache, "layers") and cache.layers and hasattr(cache.layers[0], "keys"):
        return [(layer.keys, layer.values) for layer in cache.layers]
    # transformers 4.x legacy: DynamicCache.key_cache / value_cache lists
    if hasattr(cache, "key_cache") and hasattr(cache, "value_cache"):
        return [(k, v) for k, v in zip(cache.key_cache, cache.value_cache)]
    if isinstance(cache, (list, tuple)):
        return [(layer[0], layer[1]) for layer in cache]
    raise TypeError(f"Unsupported cache type: {type(cache)!r}")


def _pairs_to_cache(pairs: Sequence[CachePair], template):
    """Rebuild a cache of the same type as ``template``."""
    if template is None or isinstance(template, (list, tuple)):
        return tuple((k, v) for k, v in pairs)
    # DynamicCache: try to construct a fresh one with update() per layer.
    try:
        from transformers.cache_utils import DynamicCache
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("transformers not available to rebuild DynamicCache") from exc

    new = DynamicCache()
    for layer_idx, (k, v) in enumerate(pairs):
        # DynamicCache.update signature is (key_states, value_states, layer_idx, cache_kwargs).
        new.update(k, v, layer_idx)
    return new


def cache_token_count(cache) -> int:
    """Return the seq_len of the cache (assumed consistent across layers)."""
    pairs = _cache_to_pairs(cache)
    if not pairs:
        return 0
    return pairs[0][0].shape[-2]


def clone_cache(cache):
    pairs = _cache_to_pairs(cache)
    cloned = [(k.clone(), v.clone()) for k, v in pairs]
    return _pairs_to_cache(cloned, cache)


def compact_dynamic_cache(
    cache,
    probe_queries: Sequence[torch.Tensor],
    target_size: float | int,
    *,
    am_fn: Callable[..., CompactionResult] = attention_match,
    solve_values: bool = True,
) -> Tuple[object, List[CompactionResult]]:
    """Compact every layer of a HuggingFace KV cache.

    Args:
        cache: DynamicCache or legacy tuple of ``(k, v)`` pairs.
        probe_queries: per-layer probe Q tensors, each ``[batch, num_heads, q, head_dim]``.
                       For GQA/MQA ``num_heads`` here must be ``num_kv_heads`` (reshape /
                       mean-pool query heads per KV group beforehand).
        target_size: int (absolute m) or float in (0, 1] (ratio).
        am_fn: AM implementation to call per layer. Defaults to ``attention_match``.
        solve_values: forwarded to ``am_fn``.

    Returns:
        (new_cache, per_layer_results)
    """
    pairs = _cache_to_pairs(cache)
    if len(probe_queries) != len(pairs):
        raise ValueError(
            f"probe_queries has {len(probe_queries)} layers, cache has {len(pairs)}"
        )

    new_pairs: List[CachePair] = []
    per_layer: List[CompactionResult] = []
    for (k, v), q_probe in zip(pairs, probe_queries):
        if k.shape[0] != 1 or v.shape[0] != 1:
            raise NotImplementedError("Only batch size 1 supported for now")
        # squeeze batch -> [num_heads, n, head_dim]
        k2, v2 = k[0], v[0]
        if q_probe.dim() == 4:
            q2 = q_probe[0]
        else:
            q2 = q_probe
        result = am_fn(k2, v2, q2, target_size, solve_values=solve_values)
        # re-add batch dim
        new_pairs.append(
            (result.keys.unsqueeze(0).contiguous(), result.values.unsqueeze(0).contiguous())
        )
        per_layer.append(result)

    return _pairs_to_cache(new_pairs, cache), per_layer
