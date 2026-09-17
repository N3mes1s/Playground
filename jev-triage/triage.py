"""
Jev-powered triage for security-scanner findings.

Motivation
----------
The two existing Playground experiments (`recursive-lm-security-audit/` and
`vulnllm-analyzer/`) both suffer from the classic scanner problem: lots of
false positives and miscalibrated severities. The RLM auditor's own
`flowise-manual-verification.md` shows its #1 CRITICAL finding was a false
positive that even an expensive adversarial-LLM validation pass "confirmed",
while several severities were off by one or two levels.

Adversarial LLM validation costs ~1 full LLM call per finding and still gets
calibration wrong. Jev is built for exactly this shape of problem: instead of
another paragraph of prose, it returns *typed, calibrated probabilities*. So we
use it as a fast, cheap triage gate that runs BEFORE (or instead of) the
expensive validation pass:

    raw findings  ->  Jev triage (calibrated)  ->  keep / drop / re-rank

For each finding we ask Jev four typed questions in a single call:
  * is_real     (Noul)  - genuine exploitable vuln vs. false positive
  * reachable   (Noul)  - vulnerable code reachable with attacker input
  * severity    (Score) - calibrated severity across 5 ordered levels
  * category    (Choice)- vulnerability class

We then apply calibrated thresholds to decide keep/drop and to re-label
severity from Jev's calibrated score rather than the scanner's guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from findings import SEVERITIES, Finding
from jev_client import Choice, JevClient, Noul, Score, SystemOneResponse

CATEGORY_CRITERIA = {
    "injection": "SQL/command/code injection, SSRF, XXE, or template injection",
    "auth": "Broken authentication, authorization, IDOR, or access control",
    "crypto": "Weak/broken cryptography, secrets handling, or randomness",
    "path_traversal": "Path traversal / arbitrary file read or write",
    "deserialization": "Insecure deserialization or unsafe object loading",
    "misconfig": "Insecure configuration, debug endpoints, or exposed methods",
    "info_leak": "Sensitive data disclosure or logging of secrets",
    "other": "None of the above, or not a security issue at all",
}


def build_questions() -> dict[str, Any]:
    """The typed question battery asked about each finding."""
    return {
        "is_real": Noul(
            instructions=(
                "Is this a genuine, exploitable security vulnerability in the "
                "described code, as opposed to a false positive, a non-issue, "
                "or a design choice that grants the attacker nothing new?"
            ),
            criteria={
                "true": "A real, exploitable vulnerability",
                "false": "False positive, non-issue, or intended design",
            },
        ),
        "reachable": Noul(
            instructions=(
                "Can the vulnerable code plausibly be reached and driven by "
                "attacker-controlled input in a realistic deployment (not only "
                "in tests or behind trusted-admin-only paths)?"
            ),
        ),
        "severity": Score(
            instructions=(
                "Rate the true severity of this vulnerability if it is real, "
                "using CVSS-style impact and exploitability reasoning. If it is "
                "clearly not a vulnerability, rate it Informational."
            ),
            criteria=list(SEVERITIES),  # Informational..Critical
        ),
        "category": Choice(
            instructions="Which vulnerability class best fits this finding?",
            criteria=CATEGORY_CRITERIA,
        ),
    }


@dataclass
class TriageResult:
    finding: Finding
    is_real: float | None = None
    reachable: float | None = None
    severity_label: str | None = None
    severity_score: float | None = None
    severity_confidence: float | None = None
    category: str | None = None
    category_confidence: float | None = None
    keep: bool = False
    reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["finding"] = self.finding.__dict__
        return d


def interpret(
    finding: Finding,
    resp: SystemOneResponse,
    *,
    is_real_threshold: float,
    reachable_threshold: float,
) -> TriageResult:
    """Apply calibrated thresholds to a Jev response -> keep/drop decision.

    Split out from the network call so it can be unit-tested offline against a
    normalized `SystemOneResponse`.
    """
    a_real = resp["is_real"].noul
    a_reach = resp["reachable"].noul
    sev = resp["severity"]
    cat = resp["category"]

    severity_label = _score_to_label(sev.score, sev.legend, sev.probabilities)

    keep = True
    reasons: list[str] = []
    if a_real is not None and a_real < is_real_threshold:
        keep = False
        reasons.append(f"is_real {a_real:.2f} < {is_real_threshold:.2f}")
    if a_reach is not None and a_reach < reachable_threshold:
        keep = False
        reasons.append(f"reachable {a_reach:.2f} < {reachable_threshold:.2f}")
    if not reasons:
        reasons.append(
            f"is_real {(_fmt(a_real))}, reachable {(_fmt(a_reach))}, "
            f"severity {severity_label}"
        )

    return TriageResult(
        finding=finding,
        is_real=a_real,
        reachable=a_reach,
        severity_label=severity_label,
        severity_score=sev.score,
        severity_confidence=sev.confidence,
        category=cat.choice,
        category_confidence=cat.confidence,
        keep=keep,
        reason="; ".join(reasons),
        usage=resp.usage,
    )


def triage_finding(
    client: JevClient,
    finding: Finding,
    *,
    is_real_threshold: float = 0.6,
    reachable_threshold: float = 0.5,
) -> TriageResult:
    questions = build_questions()
    resp = client.system_one(state=finding.state_for_jev(), questions=questions)
    return interpret(
        finding,
        resp,
        is_real_threshold=is_real_threshold,
        reachable_threshold=reachable_threshold,
    )


def triage_all(
    client: JevClient,
    findings: list[Finding],
    *,
    is_real_threshold: float = 0.6,
    reachable_threshold: float = 0.5,
    on_progress=None,
) -> list[TriageResult]:
    results: list[TriageResult] = []
    for i, f in enumerate(findings, 1):
        res = triage_finding(
            client,
            f,
            is_real_threshold=is_real_threshold,
            reachable_threshold=reachable_threshold,
        )
        results.append(res)
        if on_progress:
            on_progress(i, len(findings), res)
    return results


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _score_to_label(
    score: float | None,
    legend: dict[str, Any] | None,
    probabilities: dict[str, float] | None,
) -> str | None:
    """Map Jev's weighted Score value back to a severity label.

    Prefer the highest-probability level when a distribution is present;
    otherwise round the weighted score onto the ordered SEVERITIES list.
    """
    if probabilities:
        best = max(probabilities.items(), key=lambda kv: kv[1])[0]
        return _match_level(best)
    if score is None:
        return None
    idx = int(round(score))
    idx = max(0, min(len(SEVERITIES) - 1, idx))
    return SEVERITIES[idx]


def _match_level(label: str) -> str:
    for known in SEVERITIES:
        if known.lower() in str(label).lower():
            return known
    return str(label)


def _fmt(x: float | None) -> str:
    return f"{x:.2f}" if isinstance(x, (int, float)) else "n/a"
