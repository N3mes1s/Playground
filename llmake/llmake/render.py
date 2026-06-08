"""
Prompt templating — substitute workspace material into prompt text.

A tiny, explicit ``{{...}}`` placeholder language so prompts can pull in
inputs, shared context, and upstream artifacts. Kept separate from the runner
so the substitution rules are obvious and testable.

Placeholders:
  {{input}}        all of this target's inputs, concatenated with headers
  {{input:PATH}}   one specific input file's contents
  {{context}}      all shared context files, concatenated with headers
  {{needs:NAME}}   the compiled artifact text of upstream target NAME

If a prompt references none of {{input}} / {{inputs}} / {{needs:*}}, the
inputs and upstream artifacts are auto-appended so trivial prompts still get
their material (convenience for MVP authoring).
"""

from __future__ import annotations

import re

_PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z_]+)(?::([^}]+))?\s*\}\}")


def _join(sections: dict) -> str:
    return "\n\n".join(f"## {name}\n\n{body}" for name, body in sections.items())


def render(
    template: str,
    *,
    inputs: dict,
    context: dict,
    needs: dict,
) -> str:
    """Render ``template`` against the provided material.

    ``inputs`` / ``context`` map path -> contents; ``needs`` maps target name
    -> compiled artifact text.
    """
    used = {"input": False, "needs": False}

    def repl(m: re.Match) -> str:
        kind, arg = m.group(1), m.group(2)
        arg = arg.strip() if arg else None

        if kind in ("input", "inputs"):
            used["input"] = True
            if arg:
                return inputs.get(arg, f"[missing input: {arg}]")
            return _join(inputs)
        if kind == "context":
            if arg:
                return context.get(arg, f"[missing context: {arg}]")
            return _join(context)
        if kind == "needs":
            used["needs"] = True
            if arg:
                return needs.get(arg, f"[missing dependency: {arg}]")
            return _join(needs)
        return m.group(0)  # leave unknown placeholders untouched

    out = _PLACEHOLDER.sub(repl, template)

    # Auto-append material if the author didn't reference it explicitly.
    if not used["input"] and inputs:
        out += "\n\n# Inputs\n\n" + _join(inputs)
    if not used["needs"] and needs:
        out += "\n\n# Upstream results\n\n" + _join(needs)

    return out
