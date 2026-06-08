"""
EchoProvider — a deterministic, offline, zero-dependency provider.

This is the default backend so the whole tool runs end-to-end with no API
keys and no network. It does not call a model; it produces a stable,
content-derived "result" that:

* changes when its inputs change (so the cache / incremental build is
  observable), and
* stays identical when inputs don't (so re-builds are no-ops).

Use it for trying out workflows, for tests, and for CI. Swap to a real
provider (``anthropic``, ``claude-agent``) when you want actual inference.
"""

from __future__ import annotations

import hashlib

from .base import InferenceRequest, InferenceResult, Provider


class EchoProvider(Provider):
    name = "echo"
    kinds = ("chat", "agent")

    def run(self, request: InferenceRequest) -> InferenceResult:
        digest = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()[:12]

        # A compact, deterministic "analysis" of the prompt so the artifact
        # looks like a real compiled output and varies with the input.
        lines = [ln for ln in request.prompt.splitlines() if ln.strip()]
        preview = "\n".join(f"> {ln}" for ln in lines[:6])
        word_count = len(request.prompt.split())

        body = "\n".join([
            f"# {request.target}",
            "",
            "*Compiled by the `echo` provider (offline, deterministic — no model was called).*",
            "",
            f"- prompt fingerprint: `{digest}`",
            f"- prompt size: {word_count} words / {len(request.prompt)} chars",
            f"- inputs consumed: {', '.join(request.inputs) or '(none)'}",
            f"- kind: {request.kind}",
            "",
            "## Prompt preview",
            "",
            preview or "> (empty prompt)",
            "",
            "---",
            "Replace the `echo` provider with `anthropic` or `claude-agent`",
            "in your `llmake.yaml` to produce a real inference result here.",
            "",
        ])

        return InferenceResult(
            text=body,
            provider=self.name,
            model=request.model or "echo-1",
            meta={"fingerprint": digest, "offline": True},
        )
