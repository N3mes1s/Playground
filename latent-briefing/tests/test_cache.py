"""Tests for HF cache round-tripping and compaction plumbing."""
from __future__ import annotations

import unittest

import torch

from compaction.cache import (
    _cache_to_pairs,
    _pairs_to_cache,
    cache_token_count,
    compact_dynamic_cache,
)
from compaction.attention_matching import attention_match


def _fake_legacy_cache(n_layers=2, n=64, h=4, d=8, batch=1):
    return tuple(
        (torch.randn(batch, h, n, d), torch.randn(batch, h, n, d))
        for _ in range(n_layers)
    )


class TestCachePlumbing(unittest.TestCase):
    def test_legacy_tuple_roundtrip(self):
        cache = _fake_legacy_cache()
        pairs = _cache_to_pairs(cache)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs[0][0].shape, (1, 4, 64, 8))
        rebuilt = _pairs_to_cache(pairs, cache)
        self.assertIsInstance(rebuilt, tuple)
        self.assertTrue(torch.equal(rebuilt[0][0], cache[0][0]))

    def test_token_count(self):
        cache = _fake_legacy_cache(n=128)
        self.assertEqual(cache_token_count(cache), 128)

    def test_compact_reduces_seq_len(self):
        cache = _fake_legacy_cache(n_layers=2, n=128, h=4, d=16)
        probe_qs = [torch.randn(1, 4, 6, 16), torch.randn(1, 4, 6, 16)]
        new_cache, per_layer = compact_dynamic_cache(
            cache, probe_qs, target_size=0.25
        )
        self.assertEqual(cache_token_count(new_cache), 32)
        self.assertEqual(len(per_layer), 2)
        for r in per_layer:
            self.assertEqual(r.compact_len, 32)

    def test_compact_dynamic_cache_roundtrip(self):
        """Compaction round-trips through a real DynamicCache (no model)."""
        try:
            from transformers.cache_utils import DynamicCache
        except ImportError:
            self.skipTest("transformers not installed")

        # Build a DynamicCache directly by calling update() per layer.
        cache = DynamicCache()
        for layer_idx in range(3):
            k = torch.randn(1, 4, 96, 16)
            v = torch.randn(1, 4, 96, 16)
            cache.update(k, v, layer_idx)

        self.assertEqual(cache_token_count(cache), 96)
        probe_qs = [torch.randn(1, 4, 5, 16) for _ in range(3)]
        new_cache, per_layer = compact_dynamic_cache(cache, probe_qs, target_size=0.25)
        self.assertEqual(cache_token_count(new_cache), 24)
        self.assertEqual(len(per_layer), 3)
        # Output cache should be the same type as input (DynamicCache).
        self.assertIsInstance(new_cache, DynamicCache)


if __name__ == "__main__":
    unittest.main()
