"""Latent Briefing orchestrator <-> worker loop (experimental stub).

The Ramp Labs post describes a setup where:
  * an orchestrator agent accumulates a long trajectory / shared context,
  * between turns its KV cache is compacted via Attention Matching (AM),
  * the worker agent keeps a persistent KV cache across calls and the
    90%+ unchanged tokens reuse KV prefix caching, with only the delta re-prefilled.

Upstream (adamzweiger/compaction) only ships single-turn QA demos, so the
multi-turn harness has to live here. This module is a scaffold: it defines
the intended shape of the loop and leaves the backbone-specific KV cache
swapping as TODOs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple


@dataclass
class CompactedCache:
    """Latent-space briefing: compacted (K', V') per layer/head."""
    keys: List[Any] = field(default_factory=list)    # per-layer tensors
    values: List[Any] = field(default_factory=list)  # per-layer tensors
    source_token_count: int = 0
    compact_token_count: int = 0

    @property
    def ratio(self) -> float:
        if self.source_token_count == 0:
            return 0.0
        return self.compact_token_count / self.source_token_count


@dataclass
class WorkerState:
    """Persistent worker state across orchestrator calls."""
    prefix_cache: Optional[Any] = None        # backbone-native KV cache
    last_prefix_tokens: List[int] = field(default_factory=list)


def attention_match_compact(
    full_cache: Any,
    target_ratio: float,
    attn_matching_fn: Callable[[Any, float], CompactedCache],
) -> CompactedCache:
    """Compact `full_cache` to `target_ratio` of its size using AM.

    `attn_matching_fn` is expected to come from upstream/compaction,
    e.g. a wrapper around `compaction.methods.AM_HighestAttnKeys`.
    """
    return attn_matching_fn(full_cache, target_ratio)


def diff_prefix(prev: List[int], current: List[int]) -> Tuple[int, List[int]]:
    """Return (shared_prefix_len, new_suffix_tokens) for KV prefix cache reuse."""
    n = 0
    for a, b in zip(prev, current):
        if a != b:
            break
        n += 1
    return n, current[n:]


def briefing_step(
    orchestrator_tokens: List[int],
    worker: WorkerState,
    compact: Callable[[Any, float], CompactedCache],
    prefill_delta: Callable[[Optional[Any], List[int]], Any],
    target_ratio: float = 0.1,
) -> Tuple[Any, CompactedCache]:
    """One turn of the orchestrator<->worker handshake.

    1. Diff orchestrator's token trajectory against the worker's last prefix;
       only the delta needs to be prefilled.
    2. Prefill the delta on top of the worker's persistent KV cache.
    3. Optionally compact the resulting full cache via AM before passing it
       onward as the "latent briefing" for downstream workers.

    The heavy lifting (`prefill_delta`, `compact`) is backbone-specific and
    expected to be wired in by the caller.
    """
    shared_len, delta = diff_prefix(worker.last_prefix_tokens, orchestrator_tokens)
    full_cache = prefill_delta(worker.prefix_cache, delta)
    worker.prefix_cache = full_cache
    worker.last_prefix_tokens = list(orchestrator_tokens)

    briefing = compact(full_cache, target_ratio)
    return full_cache, briefing


if __name__ == "__main__":
    print(
        "This module is a scaffold. See README.md for the replication plan and\n"
        "upstream/ for the Attention Matching reference implementation."
    )
