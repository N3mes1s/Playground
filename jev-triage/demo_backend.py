"""
Offline stub backend for Jev, used by `cli.py --demo`.

This lets the experiment run end-to-end with no API key and no network, so the
pipeline and report format can be exercised locally. It is a crude keyword
heuristic that mimics the *shape* of a Jev response (typed answers + calibrated
probabilities) -- it is emphatically NOT Jev and its numbers are made up.

Swap `StubJevClient` for `JevClient` (the default) to hit the real model.
"""

from __future__ import annotations

import hashlib
from typing import Any

from jev_client import Answer, JevClient, SystemOneResponse
from triage import CATEGORY_CRITERIA

# Keywords that push P(real) up or down, purely for the demo.
_REAL_UP = [
    "eval", "exec(", "os.system", "child_process", "deserialize", "pickle",
    "sql", "injection", "query(`", "sequelize.query", "rce", "command",
    "hardcoded", "plaintext", "cert_none", "verify=false", "md5",
    "code execution", "arbitrary code", "forge", "bypass",
]
_REAL_DOWN = [
    "false positive", "intended", "test only", "sanitized", "parameterized",
    "uuid", "not exploitable", "informational", "documentation",
]
_CATEGORY_HINTS = {
    "injection": ["sql", "inject", "eval", "exec", "command", "ssrf", "template"],
    "auth": ["auth", "authorization", "idor", "access control", "jwt", "session"],
    "crypto": ["crypto", "encrypt", "md5", "cert", "tls", "secret", "random"],
    "path_traversal": ["path travers", "../", "arbitrary file", "directory travers"],
    "deserialization": ["deserial", "pickle", "unserialize", "unmarshal"],
    "misconfig": ["debug", "e2e", "config", "exposed", "endpoint"],
    "info_leak": ["disclosure", "leak", "plaintext", "logging"],
}


class StubJevClient(JevClient):
    def __init__(self, model: str = "jev-latest") -> None:
        # Skip real init: no key / SDK needed for the stub.
        self.api_key = "demo"
        self.model = model
        self._sdk = None

    def system_one(
        self, state: Any, questions: dict[str, Any]
    ) -> SystemOneResponse:
        text = str(state).lower()
        rnd = _det_rand(text)  # deterministic jitter per finding

        real = 0.5 + 0.11 * sum(k in text for k in _REAL_UP)
        real -= 0.28 * sum(k in text for k in _REAL_DOWN)
        real = _clamp(real + (rnd - 0.5) * 0.08)

        reachable = _clamp(0.55 + 0.1 * ("req" in text or "input" in text or "user" in text)
                           - 0.35 * ("test only" in text or "admin-only" in text)
                           + (rnd - 0.5) * 0.1)

        # severity score along Informational(0)..Critical(4)
        sev_base = 0.8
        for kw, w in (("critical", 4.0), ("rce", 3.8), ("injection", 3.2),
                      ("high", 3.0), ("medium", 2.0), ("low", 1.0)):
            if kw in text:
                sev_base = max(sev_base, w)
        sev_score = _clampf(sev_base * (0.6 + 0.4 * real), 0.0, 4.0)
        sev_probs = _one_hot_soft(sev_score)

        cat = _pick_category(text)

        answers = {
            "is_real": Answer(kind="noul", noul=round(real, 3)),
            "reachable": Answer(kind="noul", noul=round(reachable, 3)),
            "severity": Answer(
                kind="score",
                score=round(sev_score, 3),
                legend={str(i): lvl for i, lvl in enumerate(
                    ["Informational", "Low", "Medium", "High", "Critical"])},
                probabilities=sev_probs,
                confidence=round(max(sev_probs.values()), 3),
            ),
            "category": Answer(
                kind="choice",
                choice=cat,
                probabilities={cat: 0.7, "other": 0.3},
                confidence=0.7,
            ),
        }
        usage = {"input_tokens": max(64, len(text) // 4), "output_tokens": 0}
        return SystemOneResponse(answers=answers, model=self.model, usage=usage)


def _pick_category(text: str) -> str:
    for cat, hints in _CATEGORY_HINTS.items():
        if any(h in text for h in hints):
            return cat
    return "other"


def _one_hot_soft(score: float) -> dict[str, float]:
    levels = ["Informational", "Low", "Medium", "High", "Critical"]
    idx = int(round(score))
    idx = max(0, min(4, idx))
    probs = {}
    for i, lvl in enumerate(levels):
        d = abs(i - idx)
        probs[lvl] = round(max(0.02, 0.7 - 0.25 * d), 3)
    s = sum(probs.values())
    return {k: round(v / s, 3) for k, v in probs.items()}


def _det_rand(text: str) -> float:
    h = hashlib.sha256(text.encode()).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def _clampf(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))
