"""
mutations.py -- behaviour-preserving command variants, for detection-robustness testing.

Signatures match strings. The long-standing blue-team headache is that an attacker
can change the *string* without changing the *behaviour*, and the signature stops
firing. This module implements a few mild, well-known, behaviour-preserving
transformations so we can measure how brittle string matching is versus a semantic
model that judges behaviour. It is evaluation tooling, not an obfuscator: the
transforms are textbook and intentionally modest.

Each transform returns (new_command, changed) so the benchmark can score a
transform only on commands where it actually applies.
"""

from __future__ import annotations

import random
import re
from typing import Callable, Dict, Tuple

# Equivalent PowerShell / cmd flag spellings (long form <-> common short form).
_FLAG_ALIASES = [
    ("-encodedcommand", "-enc"),
    ("-executionpolicy bypass", "-ep bypass"),
    ("-noprofile", "-nop"),
    ("-noninteractive", "-noni"),
    ("-windowstyle hidden", "-w hidden"),
    ("-command", "-c"),
    ("-outfile", "-out"),
]


def case_flip(cmd: str, seed: int = 0) -> Tuple[str, bool]:
    """Randomise letter case (Windows command parsing is case-insensitive). Control:
    a good signature is usually case-insensitive too, so this should NOT defeat it."""
    rng = random.Random(seed + hash(cmd) % 1000)
    out = "".join(c.upper() if (c.isalpha() and rng.random() < 0.5) else c.lower() if c.isalpha() else c
                  for c in cmd)
    return out, out != cmd


def flag_alias(cmd: str, seed: int = 0) -> Tuple[str, bool]:
    """Swap long flag spellings for equivalent short ones (or vice versa)."""
    low = cmd.lower()
    out, changed = cmd, False
    for long, short in _FLAG_ALIASES:
        if long in low:
            out = re.sub(re.escape(long), short, out, flags=re.IGNORECASE)
            low = out.lower()
            changed = True
        elif short in low:
            out = re.sub(re.escape(short), long, out, flags=re.IGNORECASE)
            low = out.lower()
            changed = True
    return out, changed


def whitespace_pad(cmd: str, seed: int = 0) -> Tuple[str, bool]:
    """Insert extra spaces/tabs between tokens (parsers collapse runs of whitespace)."""
    out = re.sub(r" ", "  ", cmd, count=0)
    return out, out != cmd


def quote_insert(cmd: str, seed: int = 0) -> Tuple[str, bool]:
    """Insert empty quotes inside the first long alpha token (e.g. power\"\"shell) --
    a classic that the shell strips but a substring signature does not expect."""
    m = re.search(r"[A-Za-z]{6,}", cmd)
    if not m:
        return cmd, False
    tok = m.group(0)
    mid = len(tok) // 2
    spliced = tok[:mid] + '""' + tok[mid:]
    out = cmd[: m.start()] + spliced + cmd[m.end():]
    return out, True


MUTATIONS: Dict[str, Callable[[str, int], Tuple[str, bool]]] = {
    "case_flip": case_flip,
    "flag_alias": flag_alias,
    "whitespace_pad": whitespace_pad,
    "quote_insert": quote_insert,
}
