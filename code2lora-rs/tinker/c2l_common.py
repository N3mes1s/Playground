"""Shared helpers for the Tinker harnesses: relaxed exact-match, supervised
datum construction, and an evaluator that supports an optional prompt builder
(so the same code scores base, RAG, and LoRA runs)."""
import re

import tinker
import torch
from tinker_cookbook.supervised.common import datum_from_model_input_weights


def normalize(s: str) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s.rstrip(".,;:)")


def relaxed_em(pred: str, target: str) -> bool:
    """Paper's relaxed EM: whitespace-collapsed, trailing-punct-stripped,
    tolerant of model overgeneration."""
    p, t = normalize(pred), normalize(target)
    return bool(t) and (p == t or p.startswith(t))


def build_datum(tok, prefix: str, target: str, max_len: int):
    prompt_ids = tok.encode(prefix)
    completion_ids = tok.encode(target)
    eos = getattr(tok, "eos_token_id", None)
    full = prompt_ids + completion_ids + ([eos] if eos is not None else [])
    weights = torch.zeros(len(full), dtype=torch.float32)
    weights[len(prompt_ids):] = 1.0
    mi = tinker.ModelInput.from_ints(full)
    return datum_from_model_input_weights(mi, weights, max_length=max_len, reduction="mean")


def evaluate(sampling_client, tok, tasks, prompt_fn=None, max_new=12, collect=6):
    """Return (exact_match, examples, avg_prompt_tokens).

    prompt_fn(task) -> prompt string; defaults to the bare prefix. RAG passes a
    builder that prepends retrieved context, which is also what makes its
    per-query token overhead visible in avg_prompt_tokens.
    """
    if prompt_fn is None:
        prompt_fn = lambda t: t["prefix"]
    correct = 0
    tok_total = 0
    examples = []
    for t in tasks:
        prompt = prompt_fn(t)
        prompt_ids = tok.encode(prompt)
        tok_total += len(prompt_ids)
        mi = tinker.ModelInput.from_ints(prompt_ids)
        sp = tinker.SamplingParams(max_tokens=max_new, temperature=0.0, stop=["\n"])
        resp = sampling_client.sample(prompt=mi, num_samples=1, sampling_params=sp).result()
        pred = tok.decode(resp.sequences[0].tokens, skip_special_tokens=True)
        ok = relaxed_em(pred, t["target"])
        correct += ok
        if len(examples) < collect:
            examples.append((ok, t["target"], pred.strip()))
    n = max(1, len(tasks))
    return correct / n, examples, tok_total / n
