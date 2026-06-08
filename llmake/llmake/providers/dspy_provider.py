"""
DSPyProvider — the primary inference backend. Targets are compiled by DSPy
programs, not hand-tuned prompt strings.

DSPy (https://dspy.ai) treats LLM calls as typed, optimizable *programs*. This
is llmake's canonical engine; ``dspy`` is a hard dependency. Pick the program
per-target via the ``module`` param:

* ``predict`` (default) — a single ``dspy.Predict`` call.
* ``cot``               — ``dspy.ChainOfThought`` (adds a reasoning step).
* ``rlm``               — ``dspy.RLM``, the Recursive Language Model: the
                          target's *inputs* are handed to the program as a
                          Python variable and explored recursively in a
                          sandboxed REPL. Ideal for large corpora that don't
                          fit (well) in a single prompt.

Model identifiers use LiteLLM format, e.g. ``openai/gpt-4o-mini``,
``anthropic/claude-opus-4-8``, ``openrouter/moonshotai/kimi-k2.5``.

The LM is applied with ``dspy.context(lm=...)`` rather than the global
``dspy.configure``, so parallel builds (``llmake build -j N``) don't clobber
each other's configuration. Token usage and cost are read back from the LM's
call history and surfaced in the build cache / export, so artifacts carry their
own provenance.
"""

from __future__ import annotations

import dspy

from .base import InferenceRequest, InferenceResult, Provider

DEFAULT_MODEL = "openai/gpt-4o-mini"

# Params consumed by this provider itself; everything not listed here (and not
# an LM-native kwarg) is forwarded to the LiteLLM-backed ``dspy.LM``
# (api_base, api_key, reasoning_effort, ...).
_LM_KNOWN = {"temperature", "max_tokens", "cache", "num_retries"}
_PROVIDER_KNOWN = {
    "module", "sub_model", "max_iterations", "max_llm_calls", "verbose",
    "retries", "retry_backoff",
}


class Task(dspy.Signature):
    """Carry out the task described by the prompt. The prompt already contains
    all instructions and context. Respond with the final result only, formatted
    as markdown."""

    prompt: str = dspy.InputField(desc="Full task prompt with all context")
    response: str = dspy.OutputField(desc="Final result, in markdown")


class Materials(dspy.Signature):
    """Carry out the `task`, using `materials` (a mapping of source name to file
    contents) as the corpus to analyze. Explore the materials as needed and
    respond with the final result only, as markdown."""

    task: str = dspy.InputField(desc="The task to perform")
    materials: dict = dspy.InputField(desc="Mapping of source path -> file contents")
    response: str = dspy.OutputField(desc="Final result, in markdown")


def _usage_meta(*lms) -> dict:
    """Aggregate token usage and cost across one or more LM histories."""
    in_tok = out_tok = calls = 0
    cost = 0.0
    have_cost = False
    for lm in lms:
        for h in getattr(lm, "history", []) or []:
            calls += 1
            u = h.get("usage") or {}
            in_tok += int(u.get("prompt_tokens", 0) or 0)
            out_tok += int(u.get("completion_tokens", 0) or 0)
            c = h.get("cost")
            if c is not None:
                cost += float(c)
                have_cost = True
    meta = {"llm_calls": calls, "input_tokens": in_tok, "output_tokens": out_tok}
    if have_cost:
        meta["cost_usd"] = round(cost, 6)
    return meta


class DSPyProvider(Provider):
    name = "dspy"
    kinds = ("chat", "agent")

    def run(self, request: InferenceRequest) -> InferenceResult:
        params = dict(request.params)
        module = str(params.pop("module", "predict")).lower()
        model = request.model or DEFAULT_MODEL

        lm_kwargs = {
            "max_tokens": int(params.get("max_tokens", 4096)),
            "cache": bool(params.get("cache", True)),
            "num_retries": int(params.get("num_retries", 3)),
        }
        if params.get("temperature") is not None:
            lm_kwargs["temperature"] = float(params["temperature"])
        for key, value in params.items():
            if key not in _LM_KNOWN and key not in _PROVIDER_KNOWN:
                lm_kwargs[key] = value  # forward to LiteLLM (api_base, etc.)

        lm = dspy.LM(model, **lm_kwargs)
        sub_model = params.get("sub_model")
        sub_lm = dspy.LM(sub_model, **lm_kwargs) if sub_model else lm

        with dspy.context(lm=lm):
            if module == "rlm":
                program = dspy.RLM(
                    Materials,
                    max_iterations=int(params.get("max_iterations", 20)),
                    max_llm_calls=int(params.get("max_llm_calls", 50)),
                    verbose=bool(params.get("verbose", False)),
                    sub_lm=sub_lm,
                )
                pred = program(task=request.prompt, materials=request.inputs)
            elif module in ("cot", "chainofthought", "chain_of_thought"):
                pred = dspy.ChainOfThought(Task)(prompt=request.prompt)
            elif module == "predict":
                pred = dspy.Predict(Task)(prompt=request.prompt)
            else:
                raise ValueError(
                    f"unknown dspy module {module!r}; use predict | cot | rlm"
                )

        meta = _usage_meta(lm, sub_lm) if sub_lm is not lm else _usage_meta(lm)
        meta["module"] = module
        return InferenceResult(
            text=pred.response, provider=self.name, model=model, meta=meta,
        )
