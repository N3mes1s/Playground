#!/usr/bin/env python3
"""Watch OE-LSU's rotation toward operating U27887 (AMS->PMI) today.

Emits one stdout line per meaningful transition so the Claude Code
Monitor tool turns each into a notification.

Events tracked (idempotent via state file):
  [MLA landed]        — OE-LSU on the ground at Malta (turnaround starts)
  [U27974 airborne]   — return leg MLA->AMS has departed
  [back at AMS]       — OE-LSU landed at AMS (pre-U27887 turnaround)
  [U27887 AIRBORNE]   — YOUR FLIGHT has departed AMS->PMI
  [U27887 landed PMI] — your flight arrived (exits)
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
DATE = os.environ.get("WATCH_DATE", "2026-07-10").strip()
REG = os.environ.get("WATCH_REG", "OE-LSU").strip()
FLIGHT = os.environ.get("WATCH_FLIGHT", "U27887").strip()
POLL_S = int(os.environ.get("POLL_INTERVAL", "180"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/tmp/oe_lsu_watch_state.json"))

if not TOKEN:
    print("[fatal] FR24_TOKEN not set", flush=True)
    sys.exit(1)


def emit(m: str) -> None:
    print(m, flush=True)


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
    return {"mla_landed": False, "u27974_air": False, "back_ams": False,
            "u27887_air": False, "u27887_done": False, "last_flight": None}


def save_state(s: dict) -> None:
    STATE_FILE.write_text(json.dumps(s))


def main() -> None:
    st = load_state()
    emit(f"[info] watching {REG} rotation toward {FLIGHT} on {DATE}, poll {POLL_S}s")

    while True:
        try:
            # --- summary of the reg's flights today ---
            res = get("/flight-summary/full",
                      flight_datetime_from=f"{DATE}T00:00:00",
                      flight_datetime_to=f"{DATE}T23:59:59",
                      registrations=REG)
            flights = sorted((res.get("data") or []),
                             key=lambda x: x.get("datetime_takeoff") or "")

            for f in flights:
                fn = f.get("flight")
                # MLA arrival
                if fn == "U27973" and f.get("flight_ended") and not st["mla_landed"]:
                    st["mla_landed"] = True; save_state(st)
                    emit(f"[MLA landed] {REG} on the ground at Malta "
                         f"{f.get('datetime_landed')} — turnaround begins")
                # return leg airborne / landed
                if fn == "U27974":
                    if not st["u27974_air"]:
                        st["u27974_air"] = True; save_state(st)
                        emit(f"[U27974 airborne] {REG} departed Malta "
                             f"{f.get('datetime_takeoff')} back to AMS")
                    if f.get("flight_ended") and not st["back_ams"]:
                        st["back_ams"] = True; save_state(st)
                        emit(f"[back at AMS] {REG} landed AMS "
                             f"{f.get('datetime_landed')} — next stop should be "
                             f"{FLIGHT} (your flight), ~2h turnaround")
                # YOUR flight
                if fn == FLIGHT:
                    if not st["u27887_air"]:
                        st["u27887_air"] = True; save_state(st)
                        emit(f"[{FLIGHT} AIRBORNE — YOUR FLIGHT] {f.get('reg')} "
                             f"({f.get('type')}) departed {f.get('orig_iata')} at "
                             f"{f.get('datetime_takeoff')}, runway "
                             f"{f.get('runway_takeoff','?')}")
                    if f.get("flight_ended") and not st["u27887_done"]:
                        st["u27887_done"] = True; save_state(st)
                        emit(f"[{FLIGHT} landed] {f.get('reg')} arrived "
                             f"{f.get('dest_iata')} at {f.get('datetime_landed')}, "
                             f"runway {f.get('runway_landed','?')} — flight complete")
                        emit("[info] all events observed, exiting")
                        return

            # --- live position for richer in-flight signal ---
            live = get("/live/flight-positions/full", registrations=REG)
            for f in (live.get("data") or []):
                cur = f.get("flight")
                if cur != st.get("last_flight"):
                    st["last_flight"] = cur; save_state(st)
                    emit(f"[now flying] {REG} is operating {cur} "
                         f"{f.get('orig_iata')}->{f.get('dest_iata')} "
                         f"(alt {f.get('alt')}ft)")

        except urllib.error.HTTPError as e:
            if e.code in (400, 404, 429):
                if e.code == 429:
                    time.sleep(POLL_S)
            else:
                emit(f"[poll error] HTTP {e.code}: {e.reason}")
        except Exception as e:
            emit(f"[poll error] {type(e).__name__}: {e}")

        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
