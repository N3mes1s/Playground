"""
Finding model + parsers.

A `Finding` is one raw claim produced by an upstream security scanner (for this
repo, the RLM auditor in `recursive-lm-security-audit/` or the VulnLLM-R
analyzer in `vulnllm-analyzer/`). Jev triage then decides whether each one is a
real, reachable vulnerability and re-calibrates its severity.

Two input formats are supported:

1. JSON: a list of objects (see `example_findings.json`).
2. Markdown: the report style produced by the RLM auditor, where findings are
   `###` headers like `VULN-01: ...` or `1. Remote Code Execution ...` with
   **Location**/**File**/**Severity**/**CWE** fields underneath.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]


@dataclass
class Finding:
    id: str
    title: str
    description: str = ""
    severity: str = "Unknown"
    file: str = ""
    cwe: str = ""
    code: str = ""  # optional code snippet / evidence
    source: str = ""  # which scanner produced it

    def state_for_jev(self) -> str:
        """Render the finding as the 'state' blob handed to Jev."""
        parts = [f"# Scanner finding: {self.title}"]
        if self.severity and self.severity != "Unknown":
            parts.append(f"Scanner-assigned severity: {self.severity}")
        if self.cwe:
            parts.append(f"CWE: {self.cwe}")
        if self.file:
            parts.append(f"File: {self.file}")
        if self.description:
            parts.append(f"\nDescription:\n{self.description.strip()}")
        if self.code:
            parts.append(f"\nCode / evidence:\n{self.code.strip()}")
        return "\n".join(parts)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def load_json_findings(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError("JSON findings must be a list (or {'findings': [...]}).")

    out: list[Finding] = []
    for i, item in enumerate(data, 1):
        out.append(
            Finding(
                id=str(item.get("id") or f"F-{i:02d}"),
                title=str(item.get("title") or item.get("name") or f"Finding {i}"),
                description=str(item.get("description") or ""),
                severity=str(item.get("severity") or "Unknown"),
                file=str(item.get("file") or item.get("location") or ""),
                cwe=str(item.get("cwe") or ""),
                code=str(item.get("code") or item.get("snippet") or ""),
                source=str(item.get("source") or "json"),
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Markdown (RLM auditor report style)
# --------------------------------------------------------------------------- #

# Matches "### VULN-01: Title", "### 1. Title", "### 1a. Title", "#### Title".
_HEADER_RE = re.compile(r"^#{2,4}\s+(?P<title>.+?)\s*$", re.MULTILINE)
_FIELD_RES = {
    "file": re.compile(r"\*\*(?:Location|File)\*\*:\s*(?P<v>.+)", re.IGNORECASE),
    "severity": re.compile(r"\*\*Severity\*\*:\s*(?P<v>.+)", re.IGNORECASE),
    "cwe": re.compile(r"\*\*CWE\*\*:\s*(?P<v>.+)", re.IGNORECASE),
}
_CODE_RE = re.compile(r"```[a-zA-Z0-9]*\n(?P<code>.*?)```", re.DOTALL)


def _looks_like_finding(title: str) -> bool:
    t = title.strip()
    if t.lower().startswith("vuln-"):
        return True
    # "1. ...", "1a. ...", "1.2 ..."
    if re.match(r"^\d+[a-z]?[.)]\s+\S", t):
        return True
    return False


def load_markdown_findings(path: str | Path) -> list[Finding]:
    text = Path(path).read_text()
    headers = list(_HEADER_RE.finditer(text))
    out: list[Finding] = []

    for idx, m in enumerate(headers):
        title = m.group("title").strip().lstrip("#").strip()
        if not _looks_like_finding(title):
            continue
        start = m.end()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(text)
        body = text[start:end]

        fields: dict[str, str] = {}
        for name, rx in _FIELD_RES.items():
            fm = rx.search(body)
            if fm:
                fields[name] = _clean(fm.group("v"))

        code_m = _CODE_RE.search(body)
        code = code_m.group("code").strip() if code_m else ""

        # A short id from a leading "VULN-01" / "1a" token if present.
        id_token = re.match(r"^(VULN-\d+|\d+[a-z]?)", title, re.IGNORECASE)
        fid = id_token.group(1) if id_token else f"F-{len(out) + 1:02d}"

        out.append(
            Finding(
                id=fid,
                title=title,
                description=_strip_fields(body).strip()[:4000],
                severity=_normalize_severity(fields.get("severity", "Unknown")),
                file=fields.get("file", ""),
                cwe=fields.get("cwe", ""),
                code=code,
                source=Path(path).name,
            )
        )
    return out


def load_findings(path: str | Path) -> list[Finding]:
    """Dispatch on file extension."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        return load_json_findings(p)
    return load_markdown_findings(p)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _clean(s: str) -> str:
    return s.strip().strip("`").strip()


def _strip_fields(body: str) -> str:
    lines = [
        ln
        for ln in body.splitlines()
        if not any(rx.search(ln) for rx in _FIELD_RES.values())
    ]
    return "\n".join(lines)


def _normalize_severity(s: str) -> str:
    s = s.strip().title()
    for known in SEVERITIES:
        if known.lower() in s.lower():
            return known
    return s or "Unknown"


def to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.__dict__ for f in findings]
