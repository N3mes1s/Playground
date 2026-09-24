"""
scan.py -- run any security detector on your own input.

    python -m security.scan --list
    python -m security.scan phishing_email email.json
    python -m security.scan waf_request '{"request": "GET /?q=1 OR 1=1 HTTP/1.1"}'
    cat alert.json | python -m security.scan soc_triage -
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cli import _load_dotenv
from jev import Jev

from .detectors import ALL, run


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--list":
        for d in ALL.values():
            print(f"{d.name:<18} {d.description}\n{'':<18} labels={d.labels}  ({d.maps_to})")
        return 0
    if len(argv) != 2 or argv[0] not in ALL:
        print(f"usage: python -m security.scan <detector> <file|json|->   detectors: {', '.join(ALL)}", file=sys.stderr)
        return 2

    name, src = argv
    raw = sys.stdin.read() if src == "-" else (Path(src).read_text() if Path(src).is_file() else src)
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        state = raw  # plain text is a valid state too

    _load_dotenv()
    (label, detail), resp = run(Jev(), ALL[name], state)
    print(json.dumps({"detector": name, "verdict": label, "detail": detail,
                      "latency_ms": round(resp.latency_ms), "model": resp.model,
                      "answers": {k: v.raw for k, v in resp.answers.items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
