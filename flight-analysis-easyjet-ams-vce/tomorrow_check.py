#!/usr/bin/env python3
"""Watch FR24 for tomorrow's U27815 / U27816 (AMS-VCE-AMS rotation).

Emits one stdout line per meaningful event. Designed to be wrapped by
the Claude Code Monitor tool so each line lands as a notification.

Events:
  [U27815 spotted]       — AMS->VCE inbound aircraft has appeared in FR24 data
  [U27815 landed VCE]    — aircraft now at Venice, turnaround starting
  [U27816 airborne]      — YOUR flight has departed Venice
  [U27816 landed AMS]    — your flight has arrived (exits)
  [poll error] / [info]  — operational signals
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

TOKEN = os.environ.get("FR24_TOKEN", "").strip()
DATE = os.environ.get("WATCH_DATE", "2026-05-27").strip()
POLL_S = int(os.environ.get("POLL_INTERVAL", "300"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/tmp/u27816_watch_state.json"))

if not TOKEN:
    print("[fatal] FR24_TOKEN env var not set", flush=True)
    sys.exit(1)


def emit(msg: str) -> None:
    print(msg, flush=True)


def get(path: str, **params: object) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"https://fr24api.flightradar24.com/api{path}?{qs}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Version": "v1",
            "Authorization": f"Bearer {TOKEN}",
            "User-Agent": "playground-flight-monitor/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {
        "u27815_seen": False,
        "u27815_landed": False,
        "u27816_seen": False,
        "u27816_landed": False,
        "reg": None,
    }


def save_state(s: dict) -> None:
    STATE_FILE.write_text(json.dumps(s))


def main() -> None:
    state = load_state()
    emit(
        f"[info] watching FR24 for U27815/U27816 on {DATE}, "
        f"poll every {POLL_S}s, state at {STATE_FILE}"
    )

    while True:
        try:
            # U27815 (AMS -> VCE) — gives us the aircraft id
            res = get(
                "/flight-summary/full",
                flight_datetime_from=f"{DATE}T00:00:00",
                flight_datetime_to=f"{DATE}T23:59:59",
                flights="U27815",
            )
            for f in res.get("data", []):
                reg = f.get("reg") or "?"
                actype = f.get("type") or "?"
                if not state["u27815_seen"]:
                    state["u27815_seen"] = True
                    state["reg"] = reg
                    save_state(state)
                    takeoff = f.get("datetime_takeoff") or "(not yet airborne)"
                    emit(
                        f"[U27815 spotted] aircraft {reg} ({actype}) — "
                        f"this airframe should operate your U27816 return. "
                        f"takeoff={takeoff}"
                    )
                if f.get("flight_ended") and not state["u27815_landed"]:
                    state["u27815_landed"] = True
                    save_state(state)
                    emit(
                        f"[U27815 landed VCE] {reg} on the ground at "
                        f"{f.get('datetime_landed')} — turnaround ~2h until "
                        f"your U27816 departure"
                    )

            # U27816 (VCE -> AMS) — your flight
            res = get(
                "/flight-summary/full",
                flight_datetime_from=f"{DATE}T00:00:00",
                flight_datetime_to=f"{DATE}T23:59:59",
                flights="U27816",
            )
            for f in res.get("data", []):
                reg = f.get("reg") or "?"
                actype = f.get("type") or "?"
                if not state["u27816_seen"]:
                    state["u27816_seen"] = True
                    save_state(state)
                    emit(
                        f"[U27816 airborne — YOUR FLIGHT] {reg} ({actype}) "
                        f"departed VCE at {f.get('datetime_takeoff')}, "
                        f"runway {f.get('runway_takeoff','?')}"
                    )
                if f.get("flight_ended") and not state["u27816_landed"]:
                    state["u27816_landed"] = True
                    save_state(state)
                    emit(
                        f"[U27816 landed AMS] {reg} on the ground at "
                        f"{f.get('datetime_landed')}, runway "
                        f"{f.get('runway_landed','?')} — flight complete"
                    )
                    emit("[info] all events observed, exiting")
                    return

        except urllib.error.HTTPError as e:
            if e.code == 429:
                emit("[poll info] rate-limited (429), backing off 2x")
                time.sleep(POLL_S)  # extra sleep
            else:
                emit(f"[poll error] HTTP {e.code}: {e.reason}")
        except Exception as e:
            emit(f"[poll error] {type(e).__name__}: {e}")

        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
