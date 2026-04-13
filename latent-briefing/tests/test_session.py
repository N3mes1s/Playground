"""Session-level correctness tests: prefix reuse must equal fresh prefill.

The key invariant for OrchestratorWorkerSession's incremental prefix-reuse
is that after ``set_orchestrator_trajectory(text)``, the resulting KV cache
is semantically identical to what a fresh ``prefill(text)`` would produce.
If the truncate+extend path produces different K/V tensors than a clean
prefill, the orchestrator's context is silently corrupted.

All tests use a tiny random-weights Llama built from config; no network.
"""
from __future__ import annotations

import os
import sys
import unittest

import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compaction import cache_token_count
from compaction.cache import _cache_to_pairs


def _kv_close(c1, c2, atol=1e-5) -> tuple:
    """Return (all_close: bool, max_abs_diff: float)."""
    p1 = _cache_to_pairs(c1)
    p2 = _cache_to_pairs(c2)
    if len(p1) != len(p2):
        return False, float("inf")
    worst = 0.0
    for (k1, v1), (k2, v2) in zip(p1, p2):
        if k1.shape != k2.shape or v1.shape != v2.shape:
            return False, float("inf")
        worst = max(worst, (k1 - k2).abs().max().item())
        worst = max(worst, (v1 - v2).abs().max().item())
    return worst <= atol, worst


class TestSessionPrefixReuse(unittest.TestCase):
    def setUp(self):
        from transformers import LlamaConfig, LlamaForCausalLM
        torch.manual_seed(0)
        self.cfg = LlamaConfig(
            vocab_size=64,
            hidden_size=32,
            intermediate_size=64,
            num_hidden_layers=2,
            num_attention_heads=4,
            num_key_value_heads=2,
            max_position_embeddings=256,
            rope_theta=10000.0,
            pad_token_id=0, bos_token_id=1, eos_token_id=2,
        )
        self.model = LlamaForCausalLM(self.cfg).eval()

    def _prefill(self, ids):
        with torch.no_grad():
            return self.model(ids, use_cache=True).past_key_values

    def _make_session(self):
        """Build an OrchestratorWorkerSession over the tiny model."""
        from briefing.model import LatentBriefingModel
        from briefing.session import OrchestratorWorkerSession

        lbm = object.__new__(LatentBriefingModel)
        lbm.model = self.model
        lbm.device = "cpu"
        lbm.dtype = torch.float32
        lbm._num_kv_heads = self.cfg.num_key_value_heads

        # Capture the raw tokenizer behavior we want: a stable id stream.
        # For this test, we feed token ids directly and bypass the tokenizer,
        # by monkey-patching the session to accept ids instead of text.
        class _IdsTok:
            pad_token = "[PAD]"; eos_token = None; eos_token_id = 2
            def __init__(self, ids_by_text):
                self._lookup = ids_by_text
            def __call__(self, text, return_tensors=None, add_special_tokens=True):
                ids = self._lookup[text]
                class R: pass
                r = R(); r.input_ids = ids.clone()
                return r
            def decode(self, ids, skip_special_tokens=False):
                # Return a stable key that round-trips through __call__.
                tup = tuple(ids.tolist())
                for text, id_tensor in self._lookup.items():
                    if tuple(id_tensor[0].tolist()) == tup:
                        return text
                # Register a new text for this id sequence so re-tokenize works.
                new_text = f"__ids_{len(self._lookup)}__"
                self._lookup[new_text] = torch.tensor([ids.tolist()])
                return new_text

        lbm.tokenizer = _IdsTok({})
        return lbm, OrchestratorWorkerSession(lbm)

    def test_shared_prefix_len(self):
        from briefing.session import _shared_prefix_len
        # Fully equal
        a = torch.tensor([[1, 2, 3]])
        b = torch.tensor([[1, 2, 3]])
        self.assertEqual(_shared_prefix_len(a, b), 3)
        # Mismatch at index 0
        self.assertEqual(_shared_prefix_len(torch.tensor([[1,2,3]]), torch.tensor([[9,2,3]])), 0)
        # Shared prefix of 2, then diverge
        self.assertEqual(_shared_prefix_len(torch.tensor([[1,2,3,4]]), torch.tensor([[1,2,9,9]])), 2)
        # a is prefix of b
        self.assertEqual(_shared_prefix_len(torch.tensor([[1,2]]), torch.tensor([[1,2,3,4]])), 2)
        # b is prefix of a
        self.assertEqual(_shared_prefix_len(torch.tensor([[1,2,3,4]]), torch.tensor([[1,2]])), 2)
        # Empty
        self.assertEqual(_shared_prefix_len(torch.tensor([[]], dtype=torch.long),
                                             torch.tensor([[1,2]])), 0)

    def test_set_trajectory_matches_fresh_prefill(self):
        """Incremental truncate+extend must equal a clean prefill of the new text."""
        lbm, sess = self._make_session()
        V = self.cfg.vocab_size
        torch.manual_seed(1)

        # Scenario 1: fresh set (no prior trajectory)
        ids1 = torch.randint(3, V, (1, 12))
        lbm.tokenizer._lookup["t1"] = ids1
        sess.set_orchestrator_trajectory("t1")
        fresh1 = self._prefill(ids1)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh1, atol=1e-5)
        self.assertTrue(ok, f"fresh set diverged: max_abs_diff={diff}")

        # Scenario 2: extend the trajectory (ids1 is a prefix of ids2)
        extra = torch.randint(3, V, (1, 6))
        ids2 = torch.cat([ids1, extra], dim=-1)
        lbm.tokenizer._lookup["t2"] = ids2
        sess.set_orchestrator_trajectory("t2")
        fresh2 = self._prefill(ids2)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh2, atol=1e-6)
        # Incremental should differ from fresh by float32 rounding at most
        # (~1e-7 in my measurements on CPU eager attention).
        self.assertTrue(ok, f"extend diverged: max_abs_diff={diff}")
        self.assertEqual(cache_token_count(sess.orchestrator.full_cache), 18)

        # Scenario 3: branch -- diverge after shared prefix
        branch = torch.cat([ids1[:, :8], torch.randint(3, V, (1, 10))], dim=-1)
        lbm.tokenizer._lookup["t3"] = branch
        sess.set_orchestrator_trajectory("t3")
        fresh3 = self._prefill(branch)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh3, atol=1e-6)
        self.assertTrue(ok, f"branch diverged: max_abs_diff={diff}")

        # Scenario 4: setting same trajectory twice -- delta should be 0
        delta, total = sess.set_orchestrator_trajectory("t3")
        self.assertEqual(delta, 0)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh3, atol=1e-6)
        self.assertTrue(ok, f"no-op set diverged: max_abs_diff={diff}")

        # Scenario 5: shrinking (new shorter than old with shared prefix)
        short = ids1[:, :6]
        lbm.tokenizer._lookup["t4"] = short
        sess.set_orchestrator_trajectory("t4")
        fresh4 = self._prefill(short)
        self.assertEqual(cache_token_count(sess.orchestrator.full_cache), 6)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh4, atol=1e-6)
        self.assertTrue(ok, f"shrink diverged: max_abs_diff={diff}")

        # Scenario 6: grow-shrink-grow-diverge oscillation (stale state regression).
        grow = torch.cat([short, torch.randint(3, V, (1, 8))], dim=-1)
        lbm.tokenizer._lookup["t5"] = grow
        sess.set_orchestrator_trajectory("t5")
        fresh5 = self._prefill(grow)
        ok, diff = _kv_close(sess.orchestrator.full_cache, fresh5, atol=1e-6)
        self.assertTrue(ok, f"grow-after-shrink diverged: max_abs_diff={diff}")

    def test_set_trajectory_reports_delta_correctly(self):
        lbm, sess = self._make_session()
        V = self.cfg.vocab_size
        torch.manual_seed(2)
        ids1 = torch.randint(3, V, (1, 10))
        lbm.tokenizer._lookup["a"] = ids1

        # Fresh set: delta == full length
        delta, total = sess.set_orchestrator_trajectory("a")
        self.assertEqual((delta, total), (10, 10))

        # Extend by 5: delta=5
        ids2 = torch.cat([ids1, torch.randint(3, V, (1, 5))], dim=-1)
        lbm.tokenizer._lookup["b"] = ids2
        delta, total = sess.set_orchestrator_trajectory("b")
        self.assertEqual((delta, total), (5, 15))

        # No change: delta=0
        delta, total = sess.set_orchestrator_trajectory("b")
        self.assertEqual((delta, total), (0, 15))


    def test_dispatch_worker_end_to_end(self):
        """Full orchestrator->worker path: set trajectory, dispatch, get a turn."""
        from briefing.model import LatentBriefingModel
        lbm, sess = self._make_session()
        V = self.cfg.vocab_size

        torch.manual_seed(5)
        ids = torch.randint(3, V, (1, 15))
        lbm.tokenizer._lookup["trajectory"] = ids
        sess.set_orchestrator_trajectory("trajectory")

        task_ids = torch.randint(3, V, (1, 4))
        lbm.tokenizer._lookup["task"] = task_ids

        turn = sess.dispatch_worker("task", target_size=0.3, max_new_tokens=4)

        self.assertEqual(turn.worker_task, "task")
        self.assertGreater(len(turn.worker_answer), 0)
        # Compaction stats: source was 15 tokens, target 0.3 -> ~5.
        self.assertEqual(turn.briefing_stats.source_tokens, 15)
        self.assertLess(turn.briefing_stats.compact_tokens, 15)
        self.assertGreaterEqual(turn.briefing_stats.compact_tokens, 1)
        # Session history recorded.
        self.assertEqual(len(sess.history), 1)
        self.assertIs(sess.history[0], turn)

        # Orchestrator cache must not have been mutated by the dispatch.
        self.assertEqual(cache_token_count(sess.orchestrator.full_cache), 15)

    def test_dispatch_without_trajectory_raises(self):
        """dispatch_worker before set_orchestrator_trajectory must raise."""
        lbm, sess = self._make_session()
        lbm.tokenizer._lookup["t"] = torch.tensor([[3, 4, 5]])
        with self.assertRaises(RuntimeError):
            sess.dispatch_worker("t", 0.3)


if __name__ == "__main__":
    unittest.main()
