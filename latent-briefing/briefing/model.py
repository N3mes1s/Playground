"""High-level wrapper: prefill context, probe, compact, resume generation.

The flow mirrors the Ramp Labs "Latent Briefing" pipeline:

    1. prefill(context_ids)         -> full KV cache (K, V) per layer
    2. probe(probe_ids, full_cache) -> per-layer Q tensors
    3. compact(full_cache, Qs, r)   -> compacted cache (K', V')
    4. generate(prompt_ids, K', V') -> answer, optionally with prefix-cache reuse
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

import torch
from torch import nn
from transformers import AutoModelForCausalLM, AutoTokenizer

from compaction import compact_dynamic_cache, cache_token_count, clone_cache
from compaction.attention_matching import CompactionResult
from .probe import ProbeCapture, align_probe_to_kv_heads


@dataclass
class BriefingStats:
    source_tokens: int
    compact_tokens: int
    probe_tokens: int
    layers: int

    @property
    def savings(self) -> float:
        if self.source_tokens == 0:
            return 0.0
        return 1.0 - self.compact_tokens / self.source_tokens


class LatentBriefingModel:
    """Small wrapper around a HF causal LM with AM-based cache compaction."""

    def __init__(
        self,
        model_name: str = "sshleifer/tiny-gpt2",
        device: str = "cpu",
        dtype: torch.dtype = torch.float32,
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        try:
            self.model = AutoModelForCausalLM.from_pretrained(model_name, dtype=dtype)
        except TypeError:
            # Older transformers use torch_dtype.
            self.model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype=dtype)
        self.model = self.model.to(device).eval()
        self.device = device
        self.dtype = dtype
        self._num_kv_heads = self._infer_num_kv_heads()

    def _infer_num_kv_heads(self) -> int:
        cfg = self.model.config
        for attr in ("num_key_value_heads", "num_kv_heads"):
            v = getattr(cfg, attr, None)
            if v is not None:
                return int(v)
        # GPT-2 / most classic models: same as num_heads.
        for attr in ("num_attention_heads", "n_head"):
            v = getattr(cfg, attr, None)
            if v is not None:
                return int(v)
        raise RuntimeError("Could not infer num_kv_heads from model config")

    # ---- primitives -------------------------------------------------------

    @torch.no_grad()
    def prefill(self, text: str) -> Tuple[torch.Tensor, object]:
        """Encode ``text`` and run a full-context forward to build a KV cache."""
        input_ids = self.tokenizer(text, return_tensors="pt").input_ids.to(self.device)
        out = self.model(input_ids=input_ids, use_cache=True, return_dict=True)
        return input_ids, out.past_key_values

    @torch.no_grad()
    def probe_queries(
        self,
        probe_text: str,
        past_cache,
    ) -> List[torch.Tensor]:
        """Run a probe forward (with past_cache attached but not written to) to
        capture per-layer Q tensors.

        We clone the cache to avoid mutating it, run with use_cache=False on
        the probe tokens, and record Q via forward pre-hooks.
        """
        probe_ids = self.tokenizer(probe_text, return_tensors="pt").input_ids.to(self.device)
        # Clone so the model's update() calls during attention don't extend the
        # original cache. We'll discard the post-probe cache.
        cache_for_probe = clone_cache(past_cache)

        capture = ProbeCapture(self.model)
        with capture.record():
            _ = self.model(
                input_ids=probe_ids,
                past_key_values=cache_for_probe,
                use_cache=True,
                return_dict=True,
            )
        # Align to KV-head count (no-op for non-GQA models).
        aligned = [align_probe_to_kv_heads(q, self._num_kv_heads) for q in capture.queries]
        return aligned

    def compact(
        self,
        past_cache,
        probe_queries: List[torch.Tensor],
        target_size: float | int,
        *,
        solve_values: bool = True,
    ) -> Tuple[object, List[CompactionResult], BriefingStats]:
        new_cache, per_layer = compact_dynamic_cache(
            past_cache, probe_queries, target_size, solve_values=solve_values,
        )
        stats = BriefingStats(
            source_tokens=cache_token_count(past_cache),
            compact_tokens=cache_token_count(new_cache),
            probe_tokens=probe_queries[0].shape[-2] if probe_queries else 0,
            layers=len(per_layer),
        )
        return new_cache, per_layer, stats

    # ---- end-to-end -------------------------------------------------------

    def brief(
        self,
        context: str,
        probe: str,
        target_size: float | int,
        *,
        solve_values: bool = True,
    ) -> Tuple[object, BriefingStats]:
        """Prefill context, probe with ``probe`` text, and return compacted cache."""
        _, full_cache = self.prefill(context)
        qs = self.probe_queries(probe, full_cache)
        compact, _, stats = self.compact(full_cache, qs, target_size,
                                         solve_values=solve_values)
        return compact, stats

    @torch.no_grad()
    def generate(
        self,
        prompt: str,
        *,
        past_cache=None,
        max_new_tokens: int = 32,
        do_sample: bool = False,
        temperature: float = 1.0,
    ) -> Tuple[str, int]:
        """Generate from ``prompt``, optionally resuming from ``past_cache``.

        When ``past_cache`` is provided, the prompt is treated as a
        continuation: only the prompt tokens are fed through, and attention
        is conditioned on the (possibly compacted) cache.

        Caller's ``past_cache`` is NOT mutated -- we clone before stepping
        so repeated calls with the same cache produce identical results.
        """
        prompt_ids = self.tokenizer(prompt, return_tensors="pt").input_ids.to(self.device)

        # We roll our own loop instead of calling model.generate() so we can
        # consistently attach a pre-existing past_cache (stock generate()
        # sometimes re-prefills from scratch depending on version).
        generated = prompt_ids
        cache = clone_cache(past_cache) if past_cache is not None else None
        for step in range(max_new_tokens):
            if step == 0:
                step_ids = prompt_ids
            else:
                step_ids = next_token  # type: ignore[has-type]
            out = self.model(
                input_ids=step_ids,
                past_key_values=cache,
                use_cache=True,
                return_dict=True,
            )
            cache = out.past_key_values
            logits = out.logits[:, -1, :]
            if do_sample:
                probs = (logits / max(temperature, 1e-6)).softmax(dim=-1)
                next_token = torch.multinomial(probs, num_samples=1)
            else:
                next_token = logits.argmax(dim=-1, keepdim=True)
            generated = torch.cat([generated, next_token], dim=-1)
            eos = self.tokenizer.eos_token_id
            if eos is not None and next_token.item() == eos:
                break

        text = self.tokenizer.decode(generated[0], skip_special_tokens=True)
        return text, generated.shape[-1]
