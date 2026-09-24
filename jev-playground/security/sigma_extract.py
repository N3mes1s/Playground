"""
sigma_extract.py -- distil SigmaHQ rules into a reproducible signature file.

Sigma is the industry-standard way blue teams write detection *rules* (signatures)
for command/process telemetry. We turn each rule's CommandLine/Image match strings
into a simple keyword signature, so we can measure how much of a real attack corpus
plain signatures cover -- the coverage that exists before any semantic model.

The extraction is deliberately *generous to signatures* (this biases against our
thesis, so the gap Jev closes is a lower bound):
  * field-level OR: any one `contains` value counts as a pattern (a rule fires if
    any of its distinctive strings appears), except `|all` groups which stay AND;
  * logsource constraints (which Sysmon channel, which product) are ignored, so a
    rule can "match" even where it would not really apply;
  * only Image / CommandLine / ParentImage / OriginalFileName fields are used,
    because our events are process-creation command lines.

Writes security/events/sigma_signatures.json. Regenerate:
    python -m security.sigma_extract --sigma <sigma-clone>
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE / "events" / "sigma_signatures.json"
_CMD_FIELDS = ("commandline", "image", "parentimage", "originalfilename", "parentcommandline")

# Common tokens that, alone, are not a signature -- they appear in ordinary
# commands. A real Sigma rule keys on a distinctive argument combo, not these.
_STOP = {
    "powershell", "powershell.exe", "cmd.exe", "cmd", "\\powershell.exe", "\\cmd.exe",
    "system32", "windows", "microsoft", "program", "programfiles", "\\windows\\",
    "http", "https", "http://", "https://", ".exe", ".dll", ".com", ".net", ".org",
    "system", "user", "users", "admin", "administrator", "local", "localhost", "host",
    "file", "files", "path", "name", "value", "true", "false", "null", "none", "temp",
    "\\temp\\", "appdata", "public", "downloads", "documents", "desktop", "/bin/", "/tmp/",
    "/usr/", "/etc/", "bash", "/bin/bash", "/bin/sh", "root", "home", "start", "stop",
    "create", "delete", "query", "select", "update", "service", "process", "network",
    "command", "script", "install", "config", "server", "client", "connect", "session",
    "-command", "-file", "invoke", "get-", "set-", "new-", "test", "run", "exec",
}


def _distinctive(tok: str) -> bool:
    t = tok.strip().lower()
    if not t or t in _STOP:
        return False
    if any(c in t for c in "\\/.:-_=$ "):  # paths, flags, API calls, ${...}
        return len(t) >= 4
    return len(t) >= 7  # a plain word must be long/specific to be a signature


def _patterns_from_selection(sel) -> list:
    pats = []
    if not isinstance(sel, dict):
        return pats
    for key, val in sel.items():
        parts = key.split("|")
        base, mods = parts[0].lower(), parts[1:]
        if base not in _CMD_FIELDS:
            continue
        vals = [str(v) for v in (val if isinstance(val, list) else [val]) if v is not None]
        if "all" in mods:  # AND group: keep if it carries real specificity
            group = [v for v in vals if len(v) >= 3]
            if group and (len(group) >= 2 or _distinctive(group[0])):
                pats.append(group)
        else:  # OR list: each value is its own single-token pattern, if distinctive
            for v in vals:
                if _distinctive(v):
                    pats.append([v])
    return pats


def extract(sigma_root: Path) -> dict:
    rules = []
    for f in glob.glob(str(sigma_root / "rules" / "**" / "*.yml"), recursive=True):
        try:
            import yaml
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        det = doc.get("detection", {})
        if not isinstance(det, dict):
            continue
        pats = []
        for name, sel in det.items():
            if name == "condition":
                continue
            if isinstance(sel, list):
                for s in sel:
                    pats += _patterns_from_selection(s)
            else:
                pats += _patterns_from_selection(sel)
        # dedup patterns
        seen, uniq = set(), []
        for p in pats:
            key = tuple(sorted(s.lower() for s in p))
            if key and key not in seen:
                seen.add(key)
                uniq.append([s.lower() for s in p])
        if uniq:
            rules.append({"title": doc.get("title", "")[:80], "patterns": uniq})
    return {"meta": {"source": "SigmaHQ/sigma (DRL-1.1)", "rules_with_patterns": len(rules),
                     "note": "generous keyword approximation; see sigma_extract.py"},
            "rules": rules}


def matches(command_text: str, sig: dict) -> str | None:
    """Return the title of the first Sigma rule whose signature matches, else None."""
    t = command_text.lower()
    for rule in sig["rules"]:
        for pat in rule["patterns"]:
            if all(tok in t for tok in pat):
                return rule["title"] or "(untitled)"
    return None


def match_count(command_text: str, sig: dict) -> int:
    """Number of distinct Sigma rules whose signature matches -- a graded score
    that is fair to signatures for ROC/AUC (more rules firing = more 'suspicious')."""
    t = command_text.lower()
    n = 0
    for rule in sig["rules"]:
        if any(all(tok in t for tok in pat) for pat in rule["patterns"]):
            n += 1
    return n


def load() -> dict:
    if not OUT.exists():
        raise SystemExit(f"{OUT} missing -- run: python -m security.sigma_extract --sigma <clone>")
    return json.loads(OUT.read_text())


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma", required=True, type=Path)
    args = ap.parse_args(argv)
    sig = extract(args.sigma)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(sig))
    npat = sum(len(r["patterns"]) for r in sig["rules"])
    print(f"wrote {OUT}: {sig['meta']['rules_with_patterns']} rules, {npat} patterns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
