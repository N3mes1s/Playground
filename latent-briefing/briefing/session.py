"""Multi-agent orchestrator/worker session with Latent Briefing.

Models the loop described in the Ramp Labs announcement:

  * An orchestrator agent accumulates a long shared context / trajectory.
  * On each turn the worker receives a *latent briefing*: the orchestrator's
    KV cache, compacted against the worker's probe (its question/task).
  * The worker keeps a persistent KV prefix of the orchestrator trajectory
    across turns so that 90%+ of tokens reuse via prefix caching; only the
    delta is re-prefilled + compacted.

This implementation operates on token ids for the prefix-reuse bookkeeping
and delegates heavy lifting to ``LatentBriefingModel``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import torch

from .model import LatentBriefingModel, BriefingStats


@dataclass
class AgentTurn:
    worker_task: str
    worker_answer: str
    briefing_stats: BriefingStats
    orchestrator_tokens: int
    delta_tokens: int  # tokens actually prefilled this turn (vs. reused)


@dataclass
class OrchestratorState:
    """Accumulated orchestrator trajectory, token-level."""
    input_ids: Optional[torch.Tensor] = None  # [1, T]
    full_cache: Optional[object] = None       # DynamicCache of the trajectory

    @property
    def token_count(self) -> int:
        return 0 if self.input_ids is None else int(self.input_ids.shape[-1])


def _shared_prefix_len(a: torch.Tensor, b: torch.Tensor) -> int:
    """Return length of the longest shared prefix between two [1, T] id tensors."""
    if a is None or b is None:
        return 0
    n = min(a.shape[-1], b.shape[-1])
    if n == 0:
        return 0
    eq = (a[0, :n] == b[0, :n])
    # first False index -> prefix length
    if bool(eq.all()):
        return int(n)
    first_mismatch = int((~eq).nonzero(as_tuple=False)[0].item())
    return first_mismatch


class OrchestratorWorkerSession:
    """Stateful session coordinating one orchestrator and many worker calls."""

    def __init__(self, lbm: LatentBriefingModel):
        self.lbm = lbm
        self.orchestrator = OrchestratorState()
        self.history: List[AgentTurn] = []

    # ---- orchestrator bookkeeping ----------------------------------------

    def set_orchestrator_trajectory(self, trajectory_text: str) -> Tuple[int, int]:
        """Replace/extend the orchestrator's shared context.

        Returns ``(delta_tokens_prefilled, total_trajectory_tokens)``.
        If the new trajectory shares a prefix with the old one, only the
        tail is re-prefilled on top of the retained KV cache.
        """
        new_ids = self.lbm.tokenizer(trajectory_text, return_tensors="pt").input_ids.to(self.lbm.device)

        shared = _shared_prefix_len(self.orchestrator.input_ids, new_ids) \
            if self.orchestrator.input_ids is not None else 0
        delta_ids = new_ids[:, shared:]

        # Truncate cache to the shared prefix then extend with delta.
        cache = self.orchestrator.full_cache
        if cache is not None and shared > 0:
            cache = _truncate_cache(cache, shared)
        elif cache is not None and shared == 0:
            cache = None  # complete reset

        if delta_ids.shape[-1] > 0:
            with torch.no_grad():
                out = self.lbm.model(
                    input_ids=delta_ids,
                    past_key_values=cache,
                    use_cache=True,
                    return_dict=True,
                )
            cache = out.past_key_values

        self.orchestrator.input_ids = new_ids
        self.orchestrator.full_cache = cache
        return int(delta_ids.shape[-1]), int(new_ids.shape[-1])

    def append_to_orchestrator(self, extra_text: str) -> Tuple[int, int]:
        """Append text to the orchestrator's trajectory (always a pure delta)."""
        if self.orchestrator.input_ids is None:
            return self.set_orchestrator_trajectory(extra_text)
        full_text = self.lbm.tokenizer.decode(
            self.orchestrator.input_ids[0], skip_special_tokens=False,
        ) + extra_text
        return self.set_orchestrator_trajectory(full_text)

    # ---- worker dispatch -------------------------------------------------

    def dispatch_worker(
        self,
        task: str,
        target_size: float | int,
        *,
        max_new_tokens: int = 48,
        solve_values: bool = True,
    ) -> AgentTurn:
        """Compact the orchestrator cache against ``task`` and generate an answer."""
        if self.orchestrator.full_cache is None:
            raise RuntimeError("Set orchestrator trajectory before dispatching workers.")

        # 1. probe the shared cache with the worker's task
        probe_qs = self.lbm.probe_queries(task, self.orchestrator.full_cache)
        # 2. compact
        compact_cache, _, stats = self.lbm.compact(
            self.orchestrator.full_cache, probe_qs, target_size,
            solve_values=solve_values,
        )
        # 3. generate with the compacted cache as prefix
        answer, _ = self.lbm.generate(
            task, past_cache=compact_cache, max_new_tokens=max_new_tokens,
        )
        turn = AgentTurn(
            worker_task=task,
            worker_answer=answer,
            briefing_stats=stats,
            orchestrator_tokens=self.orchestrator.token_count,
            delta_tokens=0,
        )
        self.history.append(turn)
        return turn


# ---- cache utilities --------------------------------------------------------


def _truncate_cache(cache, keep_len: int):
    """Return a new cache keeping only the first ``keep_len`` tokens per layer."""
    from compaction.cache import _cache_to_pairs, _pairs_to_cache
    pairs = _cache_to_pairs(cache)
    truncated = [(k[..., :keep_len, :].contiguous(), v[..., :keep_len, :].contiguous())
                 for k, v in pairs]
    return _pairs_to_cache(truncated, cache)
