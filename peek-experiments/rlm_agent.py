"""A minimal but real RLM (Recursive Language Model) agent.

This is the half that experiments 1 and 2 faked. The agent answers a question
about a long CONTEXT that is too large to read directly: the context lives in a
Python REPL as a variable, and the model explores it by emitting code blocks,
reading the (truncated) output, and iterating until it emits ``FINAL:``.

It produces a genuine trajectory string -- exactly the kind PEEK's Distiller
prompt is written for -- which the caller hands to ``CachePolicy.update``.

WARNING: this executes model-generated Python. It is intended only for the
ephemeral sandbox these experiments run in. Each exec is wrapped in a wall-clock
alarm, but that is a guard rail, not real isolation.
"""

from __future__ import annotations

import contextlib
import io
import re
import signal
import traceback
from dataclasses import dataclass

from peek.llm.base import LMClient

_CODE_BLOCK = re.compile(r"```(?:python)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_FINAL = re.compile(r"FINAL:\s*(.*)", re.DOTALL)


@dataclass
class RLMResult:
    answer: str
    trajectory: str
    iterations: int          # number of REPL code-exec turns
    turns: int               # number of model calls (the cost metric)
    stopped: str             # "final" | "max_iters"


class _ExecTimeout(Exception):
    pass


def _run_code(code: str, namespace: dict, timeout_s: int) -> str:
    """Exec ``code``, returning captured stdout (or a traceback)."""

    def _alarm(signum, frame):  # noqa: ANN001
        raise _ExecTimeout()

    buf = io.StringIO()
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(timeout_s)
    try:
        with contextlib.redirect_stdout(buf):
            exec(code, namespace)  # noqa: S102 -- intentional: this is an RLM
    except _ExecTimeout:
        buf.write(f"\n[execution aborted: exceeded {timeout_s}s]")
    except Exception:  # noqa: BLE001 -- feed the error back to the model
        buf.write("\n" + traceback.format_exc())
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    return buf.getvalue()


class RLMAgent:
    """Drives one question to an answer via an LM + a persistent Python REPL."""

    def __init__(
        self,
        client: LMClient,
        *,
        max_iterations: int = 8,
        output_limit: int = 1400,
        exec_timeout_s: int = 10,
        verbose: bool = False,
    ) -> None:
        self.client = client
        self.max_iterations = max_iterations
        self.output_limit = output_limit
        self.exec_timeout_s = exec_timeout_s
        self.verbose = verbose

    def _system(self, question: str, n_chars: int, context_map: str) -> str:
        map_block = ""
        if context_map.strip():
            map_block = (
                "\nYou also have a CONTEXT MAP: orientation knowledge cached from "
                "earlier tasks on this SAME context. Trust it to navigate faster "
                "instead of rediscovering structure.\n"
                "<<<CONTEXT MAP>>>\n"
                f"{context_map.strip()}\n"
                "<<<END CONTEXT MAP>>>\n"
            )
        return (
            "You are an autonomous research agent. Answer the QUESTION about a "
            "large document called CONTEXT.\n\n"
            f"CONTEXT is too large to read in full ({n_chars:,} characters). It is "
            "preloaded in a Python REPL as the string variable `context`. The REPL "
            "state PERSISTS between your turns: variables you assign stay available.\n"
            f"{map_block}\n"
            "HOW TO WORK:\n"
            "- Each turn, reply with EXACTLY ONE Python code block, e.g.:\n"
            "  ```python\n"
            "  i = context.find('=== CHAPTER 7')\n"
            "  print(i, context[i:i+300])\n"
            "  ```\n"
            "- Whatever you print() is run and returned to you, truncated to "
            f"{self.output_limit} characters.\n"
            "- Explore by searching/slicing `context` (you may `import re`). "
            "NEVER print the whole `context`.\n"
            "- This is ACME's own handbook; its specific figures may differ from "
            "typical real-world policy. You MUST locate the answer inside "
            "`context` and verify it before answering -- never answer from prior "
            "knowledge, memory, or assumption.\n"
            "- When you have verified the answer in `context`, reply with NO code "
            "block and a single line:\n"
            "  FINAL: <your answer>\n"
            "- Be efficient: use as few turns as possible.\n\n"
            f"QUESTION: {question}\n"
        )

    def _truncate(self, text: str) -> str:
        if len(text) <= self.output_limit:
            return text
        return text[: self.output_limit] + "\n...[output truncated]"

    def run(self, *, question: str, context: str, context_map: str = "") -> RLMResult:
        namespace: dict = {"context": context}
        system = self._system(question, len(context), context_map)
        transcript: list[str] = []
        turns = 0

        for i in range(1, self.max_iterations + 1):
            prompt = system
            if transcript:
                prompt += "\n" + "\n".join(transcript)
            prompt += f"\n\n[Turn {i}] Your move:"

            reply = self.client.completion([{"role": "user", "content": prompt}]) or ""
            turns += 1

            code_match = _CODE_BLOCK.search(reply)
            if not code_match:
                # No code block => this turn is the final answer.
                final = _FINAL.search(reply)
                answer = (final.group(1) if final else reply).strip()
                if self.verbose:
                    print(f"      turn {i}: FINAL")
                transcript.append(f"[FINAL]\n{answer}")
                return RLMResult(
                    answer=answer,
                    trajectory=f"QUESTION: {question}\n\n" + "\n\n".join(transcript),
                    iterations=i - 1,
                    turns=turns,
                    stopped="final",
                )

            code = code_match.group(1).strip()
            output = self._truncate(_run_code(code, namespace, self.exec_timeout_s))
            if self.verbose:
                first = code.splitlines()[0] if code.splitlines() else ""
                print(f"      turn {i}: exec  | {first[:70]}")
            transcript.append(
                f"[Turn {i}]\nCODE:\n{code}\nREPL OUTPUT:\n{output}"
            )

        return RLMResult(
            answer="(no answer - hit max iterations)",
            trajectory=f"QUESTION: {question}\n\n" + "\n\n".join(transcript),
            iterations=self.max_iterations,
            turns=turns,
            stopped="max_iters",
        )
