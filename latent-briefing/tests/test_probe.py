"""Verify probe capture matches the model's internal post-RoPE Q.

Uses a tiny, locally-constructed Llama config (no network) so we can diff
the captured Q against the one the model uses inside attention.
"""
from __future__ import annotations

import os
import sys
import unittest

import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestProbeCapture(unittest.TestCase):
    def _build_tiny_llama(self):
        from transformers import LlamaConfig, LlamaForCausalLM

        cfg = LlamaConfig(
            vocab_size=64,
            hidden_size=32,
            intermediate_size=64,
            num_hidden_layers=2,
            num_attention_heads=4,
            num_key_value_heads=2,  # GQA
            max_position_embeddings=128,
            rope_theta=10000.0,
            pad_token_id=0,
            bos_token_id=1,
            eos_token_id=2,
        )
        torch.manual_seed(0)
        model = LlamaForCausalLM(cfg).eval()
        return cfg, model

    def test_rope_applied_on_llama_family(self):
        """Probe Q for a RoPE model must be post-RoPE."""
        cfg, model = self._build_tiny_llama()
        from briefing.probe import ProbeCapture

        input_ids = torch.randint(0, cfg.vocab_size, (1, 12))
        pc = ProbeCapture(model)
        with pc.record():
            with torch.no_grad():
                model(input_ids, use_cache=False)

        self.assertEqual(len(pc.queries), cfg.num_hidden_layers)
        summary = pc.rope_summary()
        # Both layers should have had RoPE applied.
        self.assertEqual(summary["with_rope"], cfg.num_hidden_layers,
                         f"Expected RoPE on every layer, got {summary}")
        # Shape: [B, H_query, T, D] -- query heads (pre-GQA reduction).
        head_dim = cfg.hidden_size // cfg.num_attention_heads
        self.assertEqual(pc.queries[0].shape, (1, cfg.num_attention_heads, 12, head_dim))

    def test_captured_q_matches_model_internal(self):
        """Cross-check: the captured post-RoPE Q equals the tensor the model
        actually uses inside attention. We install a second hook that records
        the Q that goes into the attention kernel via a patched apply_rotary_pos_emb.
        """
        import importlib
        cfg, model = self._build_tiny_llama()
        from briefing.probe import ProbeCapture

        # Patch the model's apply_rotary_pos_emb to tee out the post-RoPE Q
        # of the real forward pass, layer-by-layer.
        llama_mod = importlib.import_module(type(model.model.layers[0].self_attn).__module__)
        original = llama_mod.apply_rotary_pos_emb
        internal_qs: list = []

        def tee(q, k, cos, sin, unsqueeze_dim=1):
            q_out, k_out = original(q, k, cos, sin, unsqueeze_dim=unsqueeze_dim)
            internal_qs.append(q_out.detach().clone())
            return q_out, k_out

        llama_mod.apply_rotary_pos_emb = tee
        try:
            input_ids = torch.randint(0, cfg.vocab_size, (1, 10))
            pc = ProbeCapture(model)
            with pc.record():
                with torch.no_grad():
                    model(input_ids, use_cache=False)
        finally:
            llama_mod.apply_rotary_pos_emb = original

        # Our pre-hook ALSO calls apply_rotary_pos_emb (to get post-RoPE Q),
        # so tee fires twice per layer: once from our hook, once from the
        # real forward. The real-forward entries are every other one (indices
        # 1, 3, 5, ...). Verify our captured Q matches the real-forward Q.
        self.assertEqual(len(internal_qs), 2 * cfg.num_hidden_layers,
                         "expected tee to fire twice per layer")
        self.assertEqual(len(pc.queries), cfg.num_hidden_layers)
        real_qs = internal_qs[1::2]
        for layer_idx, (captured, internal) in enumerate(zip(pc.queries, real_qs)):
            self.assertEqual(captured.shape, internal.shape,
                             f"layer {layer_idx} shape mismatch")
            max_abs = (captured - internal).abs().max().item()
            self.assertLess(max_abs, 1e-5,
                            f"layer {layer_idx} Q diverged by {max_abs} from model-internal")

    def test_gqa_strategies_both_valid(self):
        """Both 'mean' and 'concat' produce correctly-shaped probes for GQA.

        Neither is strictly dominant on downstream generation quality (see
        the ablation notes in align_probe_to_kv_heads docstring and
        /tmp/gqa_real_eval.py). This test just verifies both run cleanly
        and produce the expected shapes.
        """
        from briefing.probe import align_probe_to_kv_heads

        cfg, _ = self._build_tiny_llama()  # H_q=4, H_kv=2, G=2
        H_q, H_kv = cfg.num_attention_heads, cfg.num_key_value_heads
        head_dim = cfg.hidden_size // H_q
        G = H_q // H_kv

        torch.manual_seed(11)
        Q = torch.randn(1, H_q, 5, head_dim)
        mean_probe = align_probe_to_kv_heads(Q, H_kv, strategy="mean")
        self.assertEqual(mean_probe.shape, (1, H_kv, 5, head_dim))
        concat_probe = align_probe_to_kv_heads(Q, H_kv, strategy="concat")
        self.assertEqual(concat_probe.shape, (1, H_kv, G * 5, head_dim))

        # No-op when H_q == H_kv (non-GQA).
        Q2 = torch.randn(1, H_kv, 5, head_dim)
        self.assertTrue(torch.equal(align_probe_to_kv_heads(Q2, H_kv), Q2))

        # Unknown strategy errors
        with self.assertRaises(ValueError):
            align_probe_to_kv_heads(Q, H_kv, strategy="nonsense")

    def test_gpt2_path_still_works(self):
        """The GPT-2 (no-RoPE) branch should also run and mark used_rope=False."""
        try:
            from transformers import GPT2Config, GPT2LMHeadModel
        except ImportError:
            self.skipTest("GPT-2 not available")

        cfg = GPT2Config(
            vocab_size=64, n_positions=64, n_embd=32, n_layer=2, n_head=4,
            n_inner=64, bos_token_id=1, eos_token_id=2,
        )
        torch.manual_seed(0)
        model = GPT2LMHeadModel(cfg).eval()

        from briefing.probe import ProbeCapture
        input_ids = torch.randint(0, cfg.vocab_size, (1, 8))
        pc = ProbeCapture(model)
        with pc.record():
            with torch.no_grad():
                model(input_ids, use_cache=False)
        self.assertEqual(len(pc.queries), cfg.n_layer)
        self.assertEqual(pc.rope_summary()["with_rope"], 0)

    def test_rope_failure_raises(self):
        """If apply_rotary_pos_emb fails on our pre-hook call, we MUST raise
        rather than silently fall back to pre-RoPE Q (which would produce
        meaningless AM probe scores against post-RoPE cached K)."""
        import importlib
        cfg, model = self._build_tiny_llama()
        from briefing.probe import ProbeCapture

        llama_mod = importlib.import_module(type(model.model.layers[0].self_attn).__module__)
        original = llama_mod.apply_rotary_pos_emb

        def fail_on_probe_call(*args, **kwargs):
            # Our pre-hook passes q as both q and k; the real forward passes
            # distinct tensors. Simulate an arch where only our call fails.
            if len(args) >= 2 and args[0] is args[1]:
                raise ValueError("artificial incompatibility for test")
            return original(*args, **kwargs)

        llama_mod.apply_rotary_pos_emb = fail_on_probe_call
        try:
            pc = ProbeCapture(model)
            input_ids = torch.randint(0, cfg.vocab_size, (1, 6))
            with self.assertRaises(RuntimeError) as ctx:
                with pc.record():
                    with torch.no_grad():
                        model(input_ids, use_cache=False)
            self.assertIn("apply_rotary_pos_emb failed", str(ctx.exception))
        finally:
            llama_mod.apply_rotary_pos_emb = original


if __name__ == "__main__":
    unittest.main()
