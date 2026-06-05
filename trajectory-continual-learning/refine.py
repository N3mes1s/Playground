"""Apply-time constraint satisfaction: a critique -> refine loop.

Inference can recover a preference, yet the policy still drops it at generation
time ("knew the rule, didn't apply it" -- e.g. hedged a P.S. away). The fix from
the instruction-following literature is a self-correction loop: generate, have a
critic check the output against each required guideline, and refine until all are
satisfied or a budget is hit.

  * Self-Refine (Madaan et al., 2023, arXiv:2303.17651) -- iterative refinement
    with self-feedback.
  * DeCRIM (Ferraz et al., 2024, arXiv:2410.06458) -- Decompose, Critique, Refine
    for following instructions with multiple constraints; the critic checks each
    constraint and the refiner targets the violated ones.

Note: the critic checks against the *learned lessons* (natural language), not the
hidden rules. So this closes the gap up to whatever inference recovered -- it
enforces what we know, it cannot enforce what was never learned.
"""

from __future__ import annotations

import re

from schema import Message
from text_rules import _EMOJI, _bullet_lines, _word_count

# Generic extractors that operationalize whatever a lesson says into a code check.
# They read the LESSON text (which the engine inferred from edits), never the
# hidden rules -- so this enforces the engine's own learned guidelines exactly.
_WORDLIMIT = re.compile(
    r"(?:under|below|within|max(?:imum)?(?:\s+of)?|at most|no more than|fewer than|<=?\s*)\s*(\d{2,3})\s*words",
    re.I)
_MENTION = re.compile(r"@[A-Za-z][\w-]+")
_PLACEHOLDER = re.compile(r"\[[^\]\n]{1,40}\]")


def code_findings(text: str, lessons) -> list[str]:
    """Verify in code the lessons that are mechanically checkable.

    This is the 'verifiable constraint' half of a tool-augmented critic (DeCRIM):
    an LLM eyeballing 'under 65 words' or 'use bullets' is unreliable; counting is
    not. We parse the requirement out of each inferred lesson and check it exactly.
    """
    fixes = []
    for l in lessons:
        t = l.text.lower()
        m = _WORDLIMIT.search(l.text)
        if m:
            lim, n = int(m.group(1)), _word_count(text)
            if n > lim:
                fixes.append(f"FIX: '{l.text}' -> draft is {n} words; cut to <= {lim}.")
        if "bullet" in t and _bullet_lines(text) < 2:
            fixes.append(f"FIX: '{l.text}' -> use a bulleted list with >=2 lines starting with '-'.")
        if "emoji" in t and _EMOJI.search(text) is None:
            fixes.append(f"FIX: '{l.text}' -> add at least one emoji.")
        for h in set(_MENTION.findall(l.text)):
            if h.lower() not in text.lower():
                fixes.append(f"FIX: '{l.text}' -> include the mention {h}.")
        if "placeholder" in t and _PLACEHOLDER.search(text):
            fixes.append(f"FIX: '{l.text}' -> remove [bracketed] placeholders; use concrete details.")
    return fixes

_CRITIC_SYSTEM = (
    "You are a strict, literal editor. You are given a DRAFT and a list of the "
    "user's REQUIRED guidelines. Check the draft against EACH guideline literally:\n"
    "- For any LENGTH guideline: COUNT the words in the draft and cite the number, "
    "then compare to the limit.\n"
    "- For any FORMATTING guideline (e.g. bulleted list): verify literally, e.g. "
    "count the lines that start with the required bullet marker.\n"
    "- For sign-offs, @mentions, and placeholders: check the exact text.\n"
    "Be harsh: if a guideline is even slightly violated, mark it FIX. Output one "
    "line per guideline:\n"
    "  OK: <guideline>            (only if fully satisfied)\n"
    "  FIX: <guideline> -> <what is wrong and exactly how to fix it>\n"
    "After the lines, output ALL_OK on its own line ONLY if every guideline passed."
)

_REVISE_SYSTEM = (
    "You are a writing assistant. Revise the draft so it satisfies EVERY guideline, "
    "applying the editor's fixes. Preserve the message's intent and concrete details. "
    "Output ONLY the revised artifact -- no preamble, no commentary, no code fences."
)


def critique(backend, draft: str, lessons) -> tuple[bool, str]:
    block = "\n".join(f"- {l.text}" for l in lessons)
    raw = backend.complete(
        f"DRAFT:\n{draft}\n\nREQUIRED guidelines:\n{block}", _CRITIC_SYSTEM)
    all_ok = ("ALL_OK" in raw) and ("FIX:" not in raw)
    return all_ok, raw


def generate_refined(backend, context: str, query: str, lessons,
                     max_iters: int = 2, trace: list | None = None) -> Message:
    """Generate, then critique-and-refine against the lessons until satisfied."""
    draft = backend.generate(context, query, lessons).content
    if not lessons:
        return Message(role="assistant", content=draft, features=[])

    block = "\n".join(f"- {l.text}" for l in lessons)
    for _ in range(max_iters):
        code = code_findings(draft, lessons)          # exact, tool-checked
        llm_ok, llm_fb = critique(backend, draft, lessons)  # everything else
        if trace is not None:
            trace.append({"draft": draft, "code_findings": code,
                          "llm_critique": llm_fb, "ok": (not code) and llm_ok})
        if not code and llm_ok:
            break
        feedback = "\n".join(code)
        if not llm_ok:
            feedback += ("\n" + llm_fb if feedback else llm_fb)
        draft = backend.complete(
            f"DRAFT:\n{draft}\n\nGUIDELINES:\n{block}\n\nEDITOR FEEDBACK:\n{feedback}\n\n"
            f"Rewrite the {context} so every guideline is satisfied.",
            _REVISE_SYSTEM)
    return Message(role="assistant", content=draft, features=[])
