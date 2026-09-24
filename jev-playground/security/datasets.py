"""
datasets.py -- build a labelled EDR benchmark from public detection-engineering data.

Malicious class : Atomic Red Team (https://github.com/redcanaryco/atomic-red-team, MIT).
    Each "atomic test" is a command that emulates one ATT&CK technique, so its
    technique id is ground truth. We resolve the test's default input arguments,
    normalise it into a Sysmon-EID-1-shaped process-creation event, and label it.

Tactic map     : SigmaHQ (https://github.com/SigmaHQ/sigma, DRL-1.1).
    Sigma rule tags carry both `attack.tXXXX` and `attack.<tactic>`, which gives a
    free technique->tactic lookup with no hand mapping.

Benign class   : hand-written admin / developer / IT commands in this file, chosen
    to look like attacker behaviour (base64, whoami, netstat, curl|bash of a real
    installer, PsExec by a sysadmin...). Hard negatives are the whole point.

`build_dataset()` regenerates events/edr_dataset.json from a local clone; the
committed JSON lets the benchmark run with no network and no attack payloads in
any Python source. Point --art / --sigma at your own clones to regenerate:

    git clone --depth 1 --filter=blob:none --sparse https://github.com/redcanaryco/atomic-red-team
    (cd atomic-red-team && git sparse-checkout set atomics)
    git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma
    (cd sigma && git sparse-checkout set rules/windows rules/linux)
    python -m security.datasets --art ./atomic-red-team --sigma ./sigma --per-technique 2
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).parent
DATA = HERE / "events" / "edr_dataset.json"

TACTICS = {  # ATT&CK tactic slug -> readable
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access", "discovery": "Discovery",
    "lateral-movement": "Lateral Movement", "collection": "Collection",
    "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact",
}

# Which Windows image a shell name maps to (for a realistic Image field).
_IMAGE = {
    "powershell": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "command_prompt": r"C:\Windows\System32\cmd.exe",
    "sh": "/bin/sh", "bash": "/bin/bash",
}
_PARENT = {
    "powershell": r"C:\Windows\explorer.exe", "command_prompt": r"C:\Windows\explorer.exe",
    "sh": "/usr/sbin/sshd", "bash": "/usr/sbin/sshd",
}


def _tactic_map(sigma_root: Path) -> Dict[str, str]:
    """technique-id (t1003.001) -> tactic name, harvested from Sigma rule tags."""
    out: Dict[str, str] = {}
    for f in glob.glob(str(sigma_root / "rules" / "**" / "*.yml"), recursive=True):
        try:
            text = Path(f).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        tags = re.findall(r"attack\.([a-z0-9_.-]+)", text)
        techs = [t for t in tags if re.fullmatch(r"t\d{4}(\.\d{3})?", t)]
        tacts = [TACTICS[t] for t in tags if t in TACTICS]
        if techs and tacts:
            for tech in techs:
                out.setdefault(tech, tacts[0])
                out.setdefault(tech.split(".")[0], tacts[0])
    return out


def _resolve_args(command: str, input_args: Dict[str, Any]) -> str:
    """Substitute #{arg} placeholders with their declared defaults."""
    for name, spec in (input_args or {}).items():
        default = "" if spec.get("default") is None else str(spec.get("default"))
        command = command.replace(f"#{{{name}}}", default)
    return command.strip()


def _event(shell: str, command: str, technique: str, tactic: str, name: str) -> Dict[str, Any]:
    win = shell in ("powershell", "command_prompt")
    return {
        "label": "malicious",
        "technique_id": technique.upper(),
        "tactic": tactic,
        "source": "atomic-red-team",
        "test_name": name,
        "event": {
            "EventID": 1, "Channel": "Sysmon" if win else "auditd",
            "Image": _IMAGE[shell],
            "CommandLine": command,
            "ParentImage": _PARENT[shell],
            "User": "CORP\\jsmith" if win else "jsmith",
            "IntegrityLevel": "Medium" if win else None,
        },
    }


def build_dataset(art_root: Path, sigma_root: Path, per_technique: int = 2) -> Dict[str, Any]:
    tmap = _tactic_map(sigma_root)
    mal: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for f in sorted(glob.glob(str(art_root / "atomics" / "T*" / "T*.yaml"))):
        import yaml
        try:
            doc = yaml.safe_load(Path(f).read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        tech = str(doc.get("attack_technique", "")).lower()
        if not tech:
            continue
        tactic = tmap.get(tech) or tmap.get(tech.split(".")[0]) or "unknown"
        for t in doc.get("atomic_tests", []):
            ex = t.get("executor", {}) or {}
            shell, cmd = ex.get("name"), ex.get("command")
            if shell not in _IMAGE or not cmd:
                continue
            if seen.get(tech, 0) >= per_technique:
                continue
            resolved = _resolve_args(cmd, t.get("input_arguments", {}))
            if not resolved or len(resolved) > 900:
                continue
            mal.append(_event(shell, resolved, tech, tactic, t.get("name", "")))
            seen[tech] = seen.get(tech, 0) + 1
    return {
        "meta": {
            "malicious_source": "redcanaryco/atomic-red-team (MIT)",
            "tactic_map_source": "SigmaHQ/sigma (DRL-1.1)",
            "per_technique": per_technique,
            "counts": {"malicious": len(mal), "benign": len(BENIGN)},
        },
        "malicious": mal,
        "benign": BENIGN,
    }


# --------------------------------------------------------------------------- #
# Benign baseline -- legitimate activity engineered to resemble attacks.
# These are the false-positive traps a real EDR ruleset struggles with.
# --------------------------------------------------------------------------- #
def _b(image, cmd, parent, user="CORP\\admin", integrity="High", note="", channel="Sysmon"):
    return {"label": "benign", "technique_id": "NONE", "tactic": "None", "source": "baseline",
            "test_name": note,
            "event": {"EventID": 1, "Channel": channel, "Image": image, "CommandLine": cmd,
                      "ParentImage": parent, "User": user, "IntegrityLevel": integrity}}


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SVC = r"C:\Windows\System32\services.exe"

BENIGN: List[Dict[str, Any]] = [
    _b(PS, "Get-WmiObject Win32_QuickFixEngineering | Select HotFixID", r"C:\Windows\CCM\CcmExec.exe",
       "NT AUTHORITY\\SYSTEM", "System", "SCCM patch inventory"),
    _b(PS, "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv C:\\reports\\users.csv",
       EXPLORER, note="HR access review script"),
    _b(CMD, "whoami /groups && net group \"Domain Admins\" /domain", EXPLORER,
       note="admin checking own group membership"),
    _b(CMD, "netstat -ano | findstr LISTENING", EXPLORER, note="troubleshooting a port"),
    _b(PS, "nltest /dclist:corp.local", EXPLORER, note="admin verifying DCs"),
    _b(CMD, r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName', EXPLORER,
       note="inventory script reading OS version"),
    _b(PS, "Compress-Archive -Path C:\\logs\\* -DestinationPath C:\\temp\\logs.zip", EXPLORER,
       note="collecting logs for a support case"),
    _b(PS, "Invoke-WebRequest https://get.helm.sh/helm-v3.14.0-windows-amd64.zip -OutFile helm.zip",
       EXPLORER, note="downloading a real tool"),
    _b(CMD, r'schtasks /create /tn "BackupJob" /tr "C:\scripts\backup.ps1" /sc daily /st 02:00', EXPLORER,
       note="scheduled backup"),
    _b(PS, "New-Service -Name MonitorAgent -BinaryPathName 'C:\\Program Files\\Mon\\agent.exe'",
       SVC, "NT AUTHORITY\\SYSTEM", "System", "installing a monitoring agent"),
    _b(CMD, r"PsExec.exe \\WS042 -s cmd /c ipconfig /all", EXPLORER, note="sysadmin remote troubleshooting"),
    _b(PS, "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('hello'))", EXPLORER,
       note="developer testing base64 in a REPL"),
    _b(PS, "certutil -hashfile C:\\downloads\\installer.exe SHA256", EXPLORER, note="verifying a download hash"),
    _b(CMD, "vssadmin list shadows", EXPLORER, note="admin checking shadow copies"),
    _b(PS, "Get-Process | Sort-Object CPU -Descending | Select -First 10", EXPLORER, note="perf triage"),
    _b("/usr/bin/bash", "curl -fsSL https://get.docker.com | sh", "/usr/sbin/sshd", "root", "High",
       "installing docker on a fresh host", channel="auditd"),
    _b("/usr/bin/find", "find / -perm -4000 -type f 2>/dev/null", "/bin/bash", "secops", "High",
       "auth'd SUID audit by security team", channel="auditd"),
    _b("/usr/bin/bash", "tar czf /backup/etc-$(date +%F).tgz /etc", "/usr/bin/cron", "root", "High",
       "nightly /etc backup", channel="auditd"),
    _b("/usr/bin/ssh", "ssh -i ~/.ssh/deploy_key deploy@10.0.3.9 'systemctl restart api'",
       "/bin/bash", "deploy", "High", "CI deploy step", channel="auditd"),
    _b("/usr/bin/openssl", "openssl enc -aes-256-cbc -salt -in db.sql -out db.sql.enc",
       "/bin/bash", "dba", "High", "encrypting a backup before upload", channel="auditd"),
]


def load() -> Dict[str, Any]:
    if not DATA.exists():
        raise SystemExit(f"{DATA} missing -- run: python -m security.datasets --art <clone> --sigma <clone>")
    return json.loads(DATA.read_text())


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--art", required=True, type=Path, help="atomic-red-team clone root")
    ap.add_argument("--sigma", required=True, type=Path, help="sigma clone root")
    ap.add_argument("--per-technique", type=int, default=2)
    args = ap.parse_args(argv)
    ds = build_dataset(args.art, args.sigma, args.per_technique)
    DATA.parent.mkdir(parents=True, exist_ok=True)
    DATA.write_text(json.dumps(ds, indent=1))
    m = ds["meta"]["counts"]
    tactics = sorted({e["tactic"] for e in ds["malicious"]})
    print(f"wrote {DATA}  malicious={m['malicious']} benign={m['benign']}  tactics={len(tactics)}")
    print("tactics:", ", ".join(tactics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
