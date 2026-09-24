"""
edr.py -- detection engineering on endpoint telemetry with Jev.

One process-creation event (Sysmon EID 1 / EDR / auditd shape) goes in as state;
one Jev round trip returns the whole triage verdict a Tier-1 analyst would write:

  * malicious?          noul   -- is this behaviour malicious, not just unusual
  * tactic              choice -- the ATT&CK tactic (14 + none)
  * lolbin_abuse        noul   -- a signed/native binary used for something it is not meant to do
  * obfuscated          noul   -- encoded / obfuscated command line hiding its intent
  * severity            score  -- Informational .. Critical
  * response            choice -- monitor / investigate / isolate_host

This is the layer that turns an EDR event firehose into ranked, tagged, actioned
alerts. It runs on every event because it is cheap enough to: ~500 input tokens,
~$0.00002 per event.

`triage()` returns an EdrVerdict; `explain()` renders it like an alert card.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from jev import Jev, Response, choice, noul, score

# ATT&CK enterprise tactics as choice options (ground truth uses the readable name).
TACTICS = {
    "none": "Legitimate administration or development activity; no adversary tactic",
    "Reconnaissance": "Gathering information to plan an attack",
    "Resource Development": "Establishing resources to support operations",
    "Initial Access": "Getting into the network",
    "Execution": "Running attacker-controlled code",
    "Persistence": "Maintaining a foothold across reboots/logoffs",
    "Privilege Escalation": "Gaining higher permissions",
    "Defense Evasion": "Avoiding detection (disabling tooling, clearing logs, obfuscation)",
    "Credential Access": "Stealing account names and secrets",
    "Discovery": "Enumerating the system, users, network, domain",
    "Lateral Movement": "Moving to other hosts",
    "Collection": "Gathering data of interest",
    "Command and Control": "Communicating with attacker infrastructure",
    "Exfiltration": "Stealing data out of the network",
    "Impact": "Destroying, encrypting or disrupting systems or data",
}

SEVERITY = ["Informational", "Low", "Medium", "High", "Critical"]

QUESTIONS = {
    "malicious": noul(
        "This process-creation event is malicious activity (an attacker technique), not routine "
        "administration, software deployment, development or IT troubleshooting -- even if it uses "
        "a built-in or signed tool"
    ),
    "tactic": choice("The single ATT&CK tactic that best describes what this command is doing", TACTICS),
    "lolbin_abuse": noul(
        "This is living-off-the-land abuse: a legitimate signed OS or admin binary "
        "(e.g. certutil, rundll32, regsvr32, mshta, bitsadmin, wmic, powershell, msbuild, "
        "curl, bash, openssl) invoked to do something it is not intended for -- download/execute "
        "payloads, dump credentials, bypass controls, or hide code"
    ),
    "obfuscated": noul(
        "The command line is deliberately obfuscated or encoded to hide its true behaviour "
        "(base64/-enc blobs, string concatenation, char/format tricks, excessive escaping)"
    ),
    "severity": score("If this were a real incident, how severe", SEVERITY),
    "response": choice(
        "The right automated response for a SOC",
        {
            "monitor": "Log only; benign or very low risk",
            "investigate": "Raise an alert for an analyst",
            "isolate_host": "High-confidence serious compromise; isolate the host now",
        },
    ),
}


@dataclass
class EdrVerdict:
    malicious: bool
    malicious_p: float
    tactic: str
    tactic_conf: float
    lolbin: float
    obfuscated: float
    severity: float
    severity_label: str
    response: str
    latency_ms: float
    tokens: int
    raw: Response

    @property
    def score(self) -> float:
        """A single 0-1 alert score blending maliciousness, severity and LOLBin/obfuscation."""
        return round(min(1.0, 0.6 * self.malicious_p + 0.25 * (self.severity / 4)
                         + 0.15 * max(self.lolbin, self.obfuscated)), 3)


def triage(client: Jev, event: Dict[str, Any], threshold: float = 0.5) -> EdrVerdict:
    """Run the full detection verdict on one telemetry event."""
    resp = client.ask(event, QUESTIONS)
    a = resp.answers
    return EdrVerdict(
        malicious=a["malicious"].noul >= threshold,
        malicious_p=round(a["malicious"].noul, 3),
        tactic=a["tactic"].choice,
        tactic_conf=round(a["tactic"].confidence or 0, 3),
        lolbin=round(a["lolbin_abuse"].noul, 3),
        obfuscated=round(a["obfuscated"].noul, 3),
        severity=round(a["severity"].score, 2),
        severity_label=a["severity"].label(),
        response=a["response"].choice,
        latency_ms=resp.latency_ms or 0.0,
        tokens=resp.usage.get("input_tokens", 0),
        raw=resp,
    )


def explain(event: Dict[str, Any], v: EdrVerdict) -> str:
    ev = event.get("event", event)
    verdict = "MALICIOUS" if v.malicious else "benign"
    return (
        f"score {v.score:<5} [{verdict}] p={v.malicious_p}\n"
        f"  image      : {ev.get('Image')}\n"
        f"  cmdline    : {ev.get('CommandLine', '')[:120]}\n"
        f"  tactic     : {v.tactic}  (conf {v.tactic_conf})\n"
        f"  severity   : {v.severity} ~ {v.severity_label}\n"
        f"  lolbin     : {v.lolbin}   obfuscated: {v.obfuscated}\n"
        f"  response   : {v.response}   ({v.latency_ms:.0f} ms)"
    )


def _demo() -> None:
    """Triage a handful of events from the dataset as ranked alert cards."""
    import sys

    from cli import _load_dotenv

    from .datasets import load

    _load_dotenv()
    ds = load()
    # 4 attacks across tactics + 2 benign hard negatives
    picks = ds["malicious"][:4] + ds["benign"][:2]
    client = Jev()
    cards = [(rec, triage(client, rec["event"])) for rec in picks]
    cards.sort(key=lambda rv: -rv[1].score)  # rank like a SOC queue
    print("EDR alert queue (highest score first)\n" + "=" * 60)
    for rec, v in cards:
        truth = rec["label"] + (f"/{rec['technique_id']}" if rec["label"] == "malicious" else "")
        print(f"\nground truth: {truth}")
        print(explain(rec["event"], v))
    sys.exit(0)


if __name__ == "__main__":
    _demo()
