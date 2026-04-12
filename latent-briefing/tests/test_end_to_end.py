"""End-to-end test: tiny RoPE model, full AM pipeline, no network.

Verifies that prefill -> probe -> compact -> generate executes cleanly on
an architecture that uses RoPE (Llama family) with GQA, exercising the
whole pipeline including the post-RoPE probe path and the head-group
alignment step. No weights are downloaded -- we build a tiny random
Llama from config.
"""
from __future__ import annotations

import os
import sys
import unittest

import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compaction import cache_token_count
from compaction.cache import compact_dynamic_cache


class TestEndToEndLlama(unittest.TestCase):
    def _build(self):
        from transformers import LlamaConfig, LlamaForCausalLM

        cfg = LlamaConfig(
            vocab_size=64,
            hidden_size=32,
            intermediate_size=64,
            num_hidden_layers=2,
            num_attention_heads=4,
            num_key_value_heads=2,  # GQA 2:1
            max_position_embeddings=256,
            rope_theta=10000.0,
            pad_token_id=0, bos_token_id=1, eos_token_id=2,
        )
        torch.manual_seed(0)
        return cfg, LlamaForCausalLM(cfg).eval()

    def test_generate_does_not_mutate_past_cache(self):
        """Regression: generate() must not extend the caller's past_cache.

        The HF cache's update() is in-place; calling the model with
        past_key_values=cache, use_cache=True will append the new K/V to
        the passed cache object. generate() clones internally to prevent
        this contaminating subsequent calls.
        """
        from briefing.model import LatentBriefingModel
        from compaction import cache_token_count

        # Build a tiny Llama LM and wrap it directly (skip from_pretrained).
        cfg, inner = self._build()
        lbm = object.__new__(LatentBriefingModel)
        lbm.model = inner
        lbm.device = "cpu"
        lbm.dtype = torch.float32
        lbm._num_kv_heads = cfg.num_key_value_heads
        from transformers import AutoTokenizer
        # Use a mock tokenizer: we don't need a real one since we'll feed ids.
        class _Tok:
            pad_token = "[PAD]"
            eos_token = None
            eos_token_id = 2
            def __call__(self, text, return_tensors=None, add_special_tokens=True):
                # Just produce a random but deterministic id tensor per text.
                torch.manual_seed(abs(hash(text)) % (2 ** 31))
                T = 5 + (abs(hash(text)) % 5)
                class R: pass
                r = R()
                r.input_ids = torch.randint(3, cfg.vocab_size, (1, T))
                return r
            def decode(self, ids, skip_special_tokens=False):
                return "x" * ids.shape[-1]
        lbm.tokenizer = _Tok()

        # Prefill a context.
        ctx_ids = torch.randint(3, cfg.vocab_size, (1, 24))
        with torch.no_grad():
            out = inner(ctx_ids, use_cache=True)
        cache = out.past_key_values
        n_before = cache_token_count(cache)
        self.assertEqual(n_before, 24)

        # Two successive generates from the *same* cache should not grow it.
        lbm.generate("hello", past_cache=cache, max_new_tokens=3)
        n_mid = cache_token_count(cache)
        lbm.generate("world", past_cache=cache, max_new_tokens=3)
        n_after = cache_token_count(cache)
        self.assertEqual(n_mid, n_before, "generate() mutated past_cache (1st call)")
        self.assertEqual(n_after, n_before, "generate() mutated past_cache (2nd call)")

    def test_rope_pipeline_runs_and_compacts(self):
        from briefing.probe import ProbeCapture, align_probe_to_kv_heads

        cfg, model = self._build()

        # Prefill a random "context" of length 48.
        context_ids = torch.randint(3, cfg.vocab_size, (1, 48))
        with torch.no_grad():
            out = model(context_ids, use_cache=True)
        full_cache = out.past_key_values
        self.assertEqual(cache_token_count(full_cache), 48)

        # Probe with a 6-token "question".
        probe_ids = torch.randint(3, cfg.vocab_size, (1, 6))
        pc = ProbeCapture(model)
        with pc.record():
            with torch.no_grad():
                model(probe_ids, past_key_values=full_cache, use_cache=True)

        self.assertEqual(len(pc.queries), cfg.num_hidden_layers)
        self.assertEqual(pc.rope_summary()["with_rope"], cfg.num_hidden_layers)

        # Align to KV heads (GQA: 4 query heads -> 2 KV heads).
        aligned = [align_probe_to_kv_heads(q, cfg.num_key_value_heads)
                   for q in pc.queries]
        self.assertEqual(aligned[0].shape, (1, cfg.num_key_value_heads, 6,
                                            cfg.hidden_size // cfg.num_attention_heads))

        # Compact the cache. Reset the cache to its pre-probe state first.
        # (The probe forward extended the cache; we want to compact the 48-tok one.)
        with torch.no_grad():
            fresh = model(context_ids, use_cache=True).past_key_values
        self.assertEqual(cache_token_count(fresh), 48)

        new_cache, per_layer = compact_dynamic_cache(
            fresh, aligned, target_size=0.25,
        )
        self.assertEqual(cache_token_count(new_cache), 12)  # 25% of 48
        for r in per_layer:
            self.assertEqual(r.compact_len, 12)

        # Generate from the compacted cache.
        with torch.no_grad():
            gen = model(probe_ids, past_key_values=new_cache, use_cache=True)
        self.assertIsNotNone(gen.logits)
        self.assertEqual(gen.logits.shape, (1, 6, cfg.vocab_size))


if __name__ == "__main__":
    unittest.main()
