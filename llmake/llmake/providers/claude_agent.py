"""
ClaudeAgentProvider — a *coding-agent* backend, not just a chat model.

This is the piece that satisfies "access to general-purpose coding agents."
Instead of a single request/response, it runs the Claude Code CLI in headless
mode (``claude -p``) inside the workspace directory, so the agent can read the
input files, run tools, and iterate before emitting its final answer. The
final stdout becomes the build artifact.

Optional: requires the ``claude`` CLI on PATH. Degrades gracefully (reports
unavailable) when it isn't, so the rest of llmake keeps working.

The agent's working directory is the workspace root, which means agent targets
can be given tasks like "refactor X and summarize what changed" — the file
edits land in the workspace and the textual summary becomes the artifact.
"""

from __future__ import annotations

import shutil
import subprocess

from .base import InferenceRequest, InferenceResult, Provider


class ClaudeAgentProvider(Provider):
    name = "claude-agent"
    kinds = ("agent", "chat")

    def available(self) -> tuple[bool, str]:
        if shutil.which("claude") is None:
            return False, "the `claude` CLI is not on PATH (install Claude Code)"
        return True, ""

    def run(self, request: InferenceRequest) -> InferenceResult:
        cmd = ["claude", "-p", request.prompt]
        if request.model:
            cmd += ["--model", request.model]

        # Run the agent inside the workspace so it can see input files and
        # write changes back into the project.
        proc = subprocess.run(
            cmd,
            cwd=str(request.workdir),
            capture_output=True,
            text=True,
            timeout=int(request.params.get("timeout", 1800)),
        )

        if proc.returncode != 0:
            raise RuntimeError(
                f"claude agent exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )

        return InferenceResult(
            text=proc.stdout.strip(),
            provider=self.name,
            model=request.model or "claude-code",
            meta={"returncode": proc.returncode, "kind": "agent"},
        )
