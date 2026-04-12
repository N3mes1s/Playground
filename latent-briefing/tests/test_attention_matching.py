"""Tests for the Attention Matching core.

Run from the latent-briefing/ directory with:
    python -m pytest tests/ -q
or standalone:
    python -m tests.test_attention_matching
"""
from __future__ import annotations

import math
import unittest

import torch

from compaction.attention_matching import (
    attention_match,
    attention_mass,
    random_baseline,
    recent_window_baseline,
)


def _attn_out(Q, K, V):
    d = K.shape[-1]
    scores = (Q @ K.transpose(-2, -1)) / math.sqrt(d)
    return scores.softmax(dim=-1) @ V


class TestAttentionMatching(unittest.TestCase):
    def setUp(self):
        torch.manual_seed(0)
        self.h, self.n, self.d = 4, 128, 32
        self.q = 8
        self.K = torch.randn(self.h, self.n, self.d)
        self.V = torch.randn(self.h, self.n, self.d)
        self.Q = torch.randn(self.h, self.q, self.d)

    def test_shapes(self):
        r = attention_match(self.K, self.V, self.Q, target_size=0.25)
        self.assertEqual(r.keys.shape, (self.h, 32, self.d))
        self.assertEqual(r.values.shape, (self.h, 32, self.d))
        self.assertEqual(r.indices.shape, (self.h, 32))
        self.assertEqual(r.source_len, self.n)
        self.assertEqual(r.compact_len, 32)
        self.assertAlmostEqual(r.ratio, 0.25)

    def test_identity_when_no_compression(self):
        r = attention_match(self.K, self.V, self.Q, target_size=1.0)
        self.assertEqual(r.compact_len, self.n)
        self.assertTrue(torch.equal(r.keys, self.K))
        self.assertTrue(torch.equal(r.values, self.V))

    def test_attention_output_preserved_better_than_random(self):
        """AM should reproduce the probe attention output more accurately
        than random or recent-window baselines at the same budget."""
        target = 0.2
        O = _attn_out(self.Q, self.K, self.V)

        am = attention_match(self.K, self.V, self.Q, target_size=target)
        O_am = _attn_out(self.Q, am.keys, am.values)

        rb = random_baseline(self.K, self.V, target_size=target)
        O_rb = _attn_out(self.Q, rb.keys, rb.values)

        rw = recent_window_baseline(self.K, self.V, target_size=target)
        O_rw = _attn_out(self.Q, rw.keys, rw.values)

        err_am = (O_am - O).pow(2).mean().item()
        err_rb = (O_rb - O).pow(2).mean().item()
        err_rw = (O_rw - O).pow(2).mean().item()

        # AM should beat both baselines handily on random data.
        self.assertLess(err_am, err_rb, f"AM {err_am:.4f} vs random {err_rb:.4f}")
        self.assertLess(err_am, err_rw, f"AM {err_am:.4f} vs recent {err_rw:.4f}")

    def test_value_solve_beats_gather(self):
        """Solving V' via least squares should beat naive gather V[idx]."""
        target = 0.15
        O = _attn_out(self.Q, self.K, self.V)

        r_solve = attention_match(self.K, self.V, self.Q, target, solve_values=True)
        r_gather = attention_match(self.K, self.V, self.Q, target, solve_values=False)

        err_solve = (_attn_out(self.Q, r_solve.keys, r_solve.values) - O).pow(2).mean().item()
        err_gather = (_attn_out(self.Q, r_gather.keys, r_gather.values) - O).pow(2).mean().item()

        self.assertLess(err_solve, err_gather + 1e-6)

    def test_attention_mass_sums_to_q(self):
        mass = attention_mass(self.Q, self.K)
        # Each probe query's softmax sums to 1, so aggregate mass sums to q per head.
        self.assertTrue(torch.allclose(mass.sum(dim=-1), torch.full((self.h,), float(self.q)),
                                       atol=1e-5))

    def test_underdetermined_case_runs(self):
        """q < m path should execute without error and still produce valid shapes."""
        K = torch.randn(2, 64, 16)
        V = torch.randn(2, 64, 16)
        Q = torch.randn(2, 3, 16)  # only 3 probe queries
        r = attention_match(K, V, Q, target_size=20)  # m=20 > q=3
        self.assertEqual(r.keys.shape, (2, 20, 16))
        self.assertEqual(r.values.shape, (2, 20, 16))
        self.assertFalse(torch.isnan(r.values).any())

    def test_deterministic_with_seed(self):
        torch.manual_seed(42)
        r1 = attention_match(self.K, self.V, self.Q, target_size=0.25)
        torch.manual_seed(42)
        r2 = attention_match(self.K, self.V, self.Q, target_size=0.25)
        self.assertTrue(torch.equal(r1.keys, r2.keys))
        self.assertTrue(torch.equal(r1.values, r2.values))


if __name__ == "__main__":
    unittest.main()
