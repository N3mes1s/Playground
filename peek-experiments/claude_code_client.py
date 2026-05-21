"""An ``LMClient`` backed by the local Claude Code CLI (``claude``).

PEEK's Distiller and Cartographer need a model behind the ``LMClient`` protocol
(``completion`` + ``last_usage``). The reference clients all call a hosted API
and need an API key. This client instead shells out to the ``claude`` binary in
non-interactive print mode -- so PEEK runs against whatever model/credentials
the local Claude Code install already has, with no API key of its own.

Each ``completion`` call runs::

    claude -p --output-format json --tools "" ...

feeding the prompt on stdin (no ARG_MAX limit) and reading the ``result`` and
``usage`` fields back out of the JSON envelope. Built-in tools are disabled and
the system prompt is replaced with a minimal one, so the call behaves as a
plain text completion rather than a coding-agent session.

Run this file directly for a one-call self-test:  python claude_code_client.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from peek.core.types import Usage

_DEFAULT_SYSTEM_PROMPT = (
    "You are a precise text-completion engine. Follow the user message exactly. "
    "When it asks for a JSON object, output only that JSON object."
)


class ClaudeCodeError(RuntimeError):
    """Raised when the ``claude`` CLI fails or returns an error envelope."""


class ClaudeCodeClient:
    """``LMClient`` that routes completions through the ``claude`` CLI.

    Parameters
    ----------
    model:
        Model alias or full name passed to ``--model`` (e.g. ``"opus"``,
        ``"sonnet"``). ``None`` uses the CLI's default model.
    timeout:
        Per-call subprocess timeout, in seconds.
    retries:
        Number of extra attempts if a call times out or errors. The `claude`
        CLI occasionally hangs or returns a transient error; a fresh process
        usually succeeds.
    system_prompt:
        Replaces Claude Code's default (coding-agent) system prompt.
    claude_bin:
        Path/name of the CLI binary.
    verbose:
        When true, print a one-line progress note to stdout before each call.
    """

    def __init__(
        self,
        model: str | None = None,
        *,
        timeout: float = 150.0,
        retries: int = 2,
        system_prompt: str = _DEFAULT_SYSTEM_PROMPT,
        claude_bin: str = "claude",
        verbose: bool = False,
    ) -> None:
        resolved = shutil.which(claude_bin)
        if resolved is None:
            raise ClaudeCodeError(
                f"the {claude_bin!r} CLI was not found on PATH -- this client "
                "must run inside an environment that has Claude Code installed."
            )
        self._bin = resolved
        # Run the subprocess from an empty, non-git directory: project-level
        # CLAUDE.md, settings, and Stop hooks (e.g. the web harness's
        # "uncommitted work" reminder) are discovered from the cwd, and would
        # otherwise leak into -- and corrupt -- a plain completion.
        self._workdir = os.path.join(tempfile.gettempdir(), "peek-claude-workdir")
        os.makedirs(self._workdir, exist_ok=True)
        self.model = model
        self.timeout = timeout
        self.retries = retries
        self.system_prompt = system_prompt
        self.verbose = verbose
        self.calls = 0
        self._last = Usage()

    def _argv(self) -> list[str]:
        argv = [
            self._bin,
            "-p",
            "--output-format", "json",
            "--tools", "",                 # pure text completion, no tool use
            "--no-session-persistence",    # don't litter ~/.claude with sessions
            "--strict-mcp-config",         # skip MCP server startup
            "--system-prompt", self.system_prompt,
        ]
        if self.model:
            argv += ["--model", self.model]
        return argv

    def completion(self, messages: list[dict]) -> str:
        prompt = "\n\n".join(str(m.get("content", "")) for m in messages)
        self.calls += 1
        if self.verbose:
            print(f"    [claude-code call #{self.calls}: {len(prompt)} prompt chars ...]")

        last_err: ClaudeCodeError | None = None
        for attempt in range(self.retries + 1):
            try:
                return self._invoke(prompt)
            except ClaudeCodeError as e:
                last_err = e
                if attempt < self.retries:
                    if self.verbose:
                        print(f"    [attempt {attempt + 1} failed ({e}); retrying ...]")
                    time.sleep(2 * (attempt + 1))
        assert last_err is not None
        raise last_err

    def _invoke(self, prompt: str) -> str:
        try:
            proc = subprocess.run(
                self._argv(),
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self._workdir,
            )
        except subprocess.TimeoutExpired as e:
            raise ClaudeCodeError(f"claude CLI timed out after {self.timeout}s") from e

        if proc.returncode != 0:
            raise ClaudeCodeError(
                f"claude CLI exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
            )

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise ClaudeCodeError(
                f"could not parse claude CLI output as JSON: {proc.stdout[:300]!r}"
            ) from e

        if data.get("is_error"):
            raise ClaudeCodeError(f"claude CLI returned an error: {data.get('result')}")

        usage = data.get("usage") or {}
        # Total input = fresh + cache-read + cache-creation tokens.
        self._last = Usage(
            input_tokens=(
                int(usage.get("input_tokens", 0) or 0)
                + int(usage.get("cache_read_input_tokens", 0) or 0)
                + int(usage.get("cache_creation_input_tokens", 0) or 0)
            ),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
        )
        return data.get("result", "") or ""

    def last_usage(self) -> Usage:
        return self._last


def _self_test() -> None:
    print("ClaudeCodeClient self-test -- one real `claude` call")
    client = ClaudeCodeClient(verbose=True)
    reply = client.completion(
        [
            {
                "role": "user",
                "content": (
                    "Return ONLY this JSON object and nothing else: "
                    '{"status": "ok", "answer": 7}'
                ),
            }
        ]
    )
    print(f"  raw result : {reply!r}")
    usage = client.last_usage()
    print(f"  usage      : {usage.input_tokens} in / {usage.output_tokens} out")

    # Confirm the reply round-trips through PEEK's own JSON extractor.
    from peek._io import extract_json

    parsed = extract_json(reply)
    print(f"  parsed JSON: {parsed}")
    ok = isinstance(parsed, dict) and parsed.get("status") == "ok"
    print(f"  self-test  : {'PASS' if ok else 'FAIL'}")


if __name__ == "__main__":
    _self_test()
