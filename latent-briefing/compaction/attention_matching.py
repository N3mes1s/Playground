"""Attention Matching (AM) for KV cache compaction.

Given a KV cache (K, V) of shape ``[num_heads, n, head_dim]`` and a probe
query tensor ``Q_probe`` of shape ``[num_heads, q, head_dim]``, AM returns
a smaller ``(K', V')`` with ``m << n`` such that

    softmax(Q_probe @ K'.T / sqrt(d)) @ V'   ~=   softmax(Q_probe @ K.T / sqrt(d)) @ V

This module implements the closed-form variant described in Zweiger et al.
*Fast KV Compaction via Attention Matching* (arXiv:2602.16284), which
Ramp Labs' "Latent Briefing" builds on for efficient memory sharing in
multi-agent systems.

The standard recipe:
  1. Select ``m`` key indices by highest aggregate attention mass against
     the probe queries.
  2. Gather ``K' = K[idx]``.
  3. Solve ``V' = argmin_V' || softmax(Q_probe K'.T) V' - softmax(Q_probe K.T) V ||``
     via least squares -- this preserves the attention *output* on the probe,
     not just the keys that were selected.

Shapes use the convention ``[num_heads, seq, head_dim]`` throughout.
Group-query attention (GQA/MQA) is handled transparently because the
num_heads dimension in the KV cache is num_kv_heads, and the probe Q is
expected to already be reshaped/expanded to that same num_kv_heads.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import torch


@dataclass
class CompactionResult:
    """Output of a compaction pass for a single layer."""

    keys: torch.Tensor       # [num_heads, m, head_dim]
    values: torch.Tensor     # [num_heads, m, head_dim]
    indices: torch.Tensor    # [num_heads, m] original positions (int64)
    source_len: int
    compact_len: int

    @property
    def ratio(self) -> float:
        if self.source_len == 0:
            return 0.0
        return self.compact_len / self.source_len


def _resolve_target(target_size: float | int, n: int) -> int:
    if isinstance(target_size, float):
        if not (0.0 < target_size <= 1.0):
            raise ValueError(f"float target_size must be in (0, 1], got {target_size}")
        m = max(1, int(round(target_size * n)))
    else:
        m = int(target_size)
    return max(1, min(m, n))


def attention_mass(
    Q_probe: torch.Tensor,
    K: torch.Tensor,
    *,
    scale: Optional[float] = None,
) -> torch.Tensor:
    """Aggregate per-key attention mass across probe queries.

    Args:
        Q_probe: ``[num_heads, q, head_dim]``
        K:       ``[num_heads, n, head_dim]``
        scale:   override for 1/sqrt(d); default is standard scaled-dot-product.

    Returns:
        ``[num_heads, n]`` -- summed softmax weights per key across probe Qs.
    """
    d = K.shape[-1]
    s = scale if scale is not None else 1.0 / math.sqrt(d)
    scores = (Q_probe @ K.transpose(-2, -1)) * s  # [h, q, n]
    attn = scores.softmax(dim=-1)
    return attn.sum(dim=-2)  # [h, n]


def _gather_heads(x: torch.Tensor, idx: torch.Tensor) -> torch.Tensor:
    """Gather along seq dim per head.

    x:   [h, n, d]
    idx: [h, m]
    out: [h, m, d]
    """
    h, n, d = x.shape
    return x.gather(dim=1, index=idx.unsqueeze(-1).expand(h, idx.shape[-1], d))


def attention_match(
    K: torch.Tensor,
    V: torch.Tensor,
    Q_probe: torch.Tensor,
    target_size: float | int,
    *,
    solve_values: bool = True,
    ridge: float = 1e-4,
    scale: Optional[float] = None,
) -> CompactionResult:
    """Compact (K, V) to target size via Attention Matching.

    Args:
        K, V:         ``[num_heads, n, head_dim]``
        Q_probe:      ``[num_heads, q, head_dim]`` probe queries
        target_size:  int (absolute m) or float in (0, 1] (ratio)
        solve_values: if True, solve V' via ridge-regularised least squares
                      on the probe attention; if False, just gather V[idx].
        ridge:        Tikhonov regularisation strength for lstsq.
        scale:        override scaled-dot-product scale (default 1/sqrt(d)).

    Returns:
        CompactionResult.
    """
    if K.shape != V.shape:
        raise ValueError(f"K {tuple(K.shape)} and V {tuple(V.shape)} must match")
    if Q_probe.shape[0] != K.shape[0] or Q_probe.shape[-1] != K.shape[-1]:
        raise ValueError(
            f"Q_probe shape {tuple(Q_probe.shape)} incompatible with K {tuple(K.shape)}"
        )

    h, n, d = K.shape
    m = _resolve_target(target_size, n)
    device = K.device

    if m >= n:
        idx = torch.arange(n, device=device).unsqueeze(0).expand(h, n)
        return CompactionResult(K, V, idx, n, n)

    s = scale if scale is not None else 1.0 / math.sqrt(d)

    # Full probe attention -- used both for key selection and the LS target.
    scores_full = (Q_probe @ K.transpose(-2, -1)) * s             # [h, q, n]
    attn_full = scores_full.softmax(dim=-1)                        # [h, q, n]
    mass = attn_full.sum(dim=-2)                                   # [h, n]

    idx = mass.topk(m, dim=-1).indices                             # [h, m]
    K_prime = _gather_heads(K, idx)                                # [h, m, d]

    if solve_values:
        # Target output on the probe: O = attn_full @ V     [h, q, d]
        O = attn_full @ V
        # Attention from probe to the selected keys: A' = softmax(Q K'^T)  [h, q, m]
        A_prime = ((Q_probe @ K_prime.transpose(-2, -1)) * s).softmax(dim=-1)

        # Solve A' V' ~= O per head. torch.linalg.lstsq is batched over leading dims.
        # Add ridge to stabilise rank-deficient cases (e.g. tiny probe q < m).
        q = A_prime.shape[1]
        if q >= m:
            solution = torch.linalg.lstsq(A_prime, O).solution    # [h, m, d]
        else:
            # Underdetermined: use ridge regression V' = (A'^T A' + lam I)^-1 A'^T O.
            # Actually when q < m we instead have fewer constraints than unknowns;
            # the minimum-norm solution is V' = A'^T (A' A'^T + lam I)^-1 O.
            At = A_prime.transpose(-2, -1)                          # [h, m, q]
            gram = A_prime @ At                                     # [h, q, q]
            eye = torch.eye(q, device=device, dtype=gram.dtype).expand_as(gram)
            solution = At @ torch.linalg.solve(gram + ridge * eye, O)
        V_prime = solution
    else:
        V_prime = _gather_heads(V, idx)

    return CompactionResult(K_prime, V_prime, idx, n, m)


# --------- Baselines ---------------------------------------------------------


def random_baseline(
    K: torch.Tensor,
    V: torch.Tensor,
    target_size: float | int,
    *,
    generator: Optional[torch.Generator] = None,
) -> CompactionResult:
    """Select m random keys per head (no attention-aware selection)."""
    h, n, d = K.shape
    m = _resolve_target(target_size, n)
    if m >= n:
        idx = torch.arange(n, device=K.device).unsqueeze(0).expand(h, n)
        return CompactionResult(K, V, idx, n, n)

    # Independent per-head sampling without replacement.
    idx = torch.stack(
        [torch.randperm(n, generator=generator, device=K.device)[:m] for _ in range(h)],
        dim=0,
    )
    return CompactionResult(_gather_heads(K, idx), _gather_heads(V, idx), idx, n, m)


def recent_window_baseline(
    K: torch.Tensor,
    V: torch.Tensor,
    target_size: float | int,
) -> CompactionResult:
    """Keep the most recent m tokens (sliding window baseline)."""
    h, n, d = K.shape
    m = _resolve_target(target_size, n)
    if m >= n:
        idx = torch.arange(n, device=K.device).unsqueeze(0).expand(h, n)
        return CompactionResult(K, V, idx, n, n)

    idx = torch.arange(n - m, n, device=K.device).unsqueeze(0).expand(h, m)
    return CompactionResult(_gather_heads(K, idx), _gather_heads(V, idx), idx, n, m)
