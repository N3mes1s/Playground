"""Fetch and analyze a single flight from the Flightradar24 API.

Usage:
    export FR24_TOKEN="<token>"
    python fr24_analyze.py --flight U27815 --date 2026-05-06
    python fr24_analyze.py --fr24-id 3f902a0d
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_BASE = "https://fr24api.flightradar24.com/api"
DATA_DIR = Path(__file__).parent / "data"


def _get(path: str, params: dict, token: str) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{API_BASE}{path}?{qs}" if qs else f"{API_BASE}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Version": "v1",
            "Authorization": f"Bearer {token}",
            "User-Agent": "playground-flight-analyzer/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def find_flight(token: str, flight: str, date: str) -> dict:
    """Resolve a flight number on a given UTC date to a single fr24 record."""
    params = {
        "flight_datetime_from": f"{date}T00:00:00",
        "flight_datetime_to": f"{date}T23:59:59",
        "flights": flight,
    }
    res = _get("/flight-summary/full", params, token)
    matches = res.get("data", [])
    if not matches:
        raise SystemExit(f"No flights found for {flight} on {date}")
    if len(matches) > 1:
        print(f"warning: {len(matches)} matches, using the first", file=sys.stderr)
    return matches[0]


def fetch_track(token: str, fr24_id: str) -> list[dict]:
    res = _get("/flight-tracks", {"flight_id": fr24_id}, token)
    return res[0]["tracks"] if res else []


# --------------------------------------------------------------------------- #
# Geometry helpers
# --------------------------------------------------------------------------- #


def haversine_nm(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R_NM = 3440.065
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R_NM * math.asin(math.sqrt(a))


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------- #
# Phase / event detection
# --------------------------------------------------------------------------- #


def detect_phases(track: list[dict]) -> list[dict]:
    """Walk through the track and label phases by altitude/vspeed heuristics."""
    phases: list[dict] = []
    cur = None
    for p in track:
        alt, vs, gs = p["alt"], p["vspeed"], p["gspeed"]
        if alt < 50 and gs < 40:
            label = "ground"
        elif alt < 50 and gs >= 40:
            label = "takeoff_roll" if not phases or phases[-1]["label"] != "climb" else "rollout"
        elif vs > 300:
            label = "climb"
        elif vs < -300:
            label = "descent"
        else:
            label = "cruise"
        if cur is None or cur["label"] != label:
            if cur:
                cur["end"] = p["timestamp"]
                phases.append(cur)
            cur = {"label": label, "start": p["timestamp"], "alt_start": alt}
        cur["alt_end"] = alt
    if cur:
        cur["end"] = track[-1]["timestamp"]
        phases.append(cur)
    return phases


def detect_go_around(track: list[dict], dest: tuple[float, float]) -> dict | None:
    """A go-around: low altitude approach (<3500 ft within 15 NM of dest) followed by a sustained climb >+1500 fpm."""
    for i, p in enumerate(track):
        if p["alt"] >= 3500 or p["alt"] == 0:
            continue
        d_dest = haversine_nm(p["lat"], p["lon"], *dest)
        if d_dest > 15:
            continue
        # look ahead 30 sec for sustained climb
        future = [q for q in track[i:i + 60] if parse_ts(q["timestamp"]) <= parse_ts(p["timestamp"]) + __import__("datetime").timedelta(seconds=60)]
        if not future:
            continue
        peak_vs = max((q["vspeed"] for q in future), default=0)
        peak_alt = max((q["alt"] for q in future), default=0)
        if peak_vs >= 1500 and peak_alt >= p["alt"] + 1500:
            return {
                "min_alt_ft": p["alt"],
                "min_alt_time": p["timestamp"],
                "min_alt_lat": p["lat"],
                "min_alt_lon": p["lon"],
                "distance_to_dest_nm": round(d_dest, 2),
                "peak_climb_vspeed_fpm": peak_vs,
            }
    return None


def detect_holds_and_deviations(track: list[dict], orig: tuple[float, float], dest: tuple[float, float]) -> dict:
    """Look for level-offs, holds (track reversals), and lateral path deviation."""
    # great-circle reference
    gc_nm = haversine_nm(*orig, *dest)
    flown_nm = 0.0
    max_offtrack_nm = 0.0
    level_offs: list[dict] = []
    heading_reversals = 0

    cruise_alt = 0
    last_alt_change_ts = None
    in_level = False
    level_start = None
    level_alt = None

    prev = None
    for p in track:
        if prev is not None:
            flown_nm += haversine_nm(prev["lat"], prev["lon"], p["lat"], p["lon"])
        # off-track distance to destination - destination heading
        d_to_dest = haversine_nm(p["lat"], p["lon"], *dest)
        d_from_orig = haversine_nm(*orig, p["lat"], p["lon"])
        # simple: max of (d_from_orig + d_to_dest - gc_nm) approximates path excess
        excess = d_from_orig + d_to_dest - gc_nm
        if excess > max_offtrack_nm:
            max_offtrack_nm = excess

        cruise_alt = max(cruise_alt, p["alt"])

        # level-off detection above 5000 ft, vspeed near zero for >= 60s
        if p["alt"] > 5000 and abs(p["vspeed"]) < 100:
            if not in_level:
                in_level = True
                level_start = p["timestamp"]
                level_alt = p["alt"]
        else:
            if in_level:
                start = parse_ts(level_start)
                end = parse_ts(p["timestamp"])
                dur = (end - start).total_seconds()
                if dur >= 60 and level_alt < cruise_alt - 2000:
                    level_offs.append({
                        "start": level_start,
                        "end": p["timestamp"],
                        "alt": level_alt,
                        "duration_s": int(dur),
                    })
                in_level = False

        # heading reversal (>120 deg change vs 5 points back)
        prev = p

    # crude reversal counter on track field
    for i in range(5, len(track)):
        a, b = track[i - 5]["track"], track[i]["track"]
        if a == 0 or b == 0:
            continue
        diff = abs(a - b) % 360
        if diff > 180:
            diff = 360 - diff
        if diff > 120:
            heading_reversals += 1

    return {
        "great_circle_nm": round(gc_nm, 1),
        "flown_nm": round(flown_nm, 1),
        "excess_nm": round(flown_nm - gc_nm, 1),
        "max_offtrack_nm": round(max_offtrack_nm, 1),
        "max_alt_ft": cruise_alt,
        "level_offs": level_offs,
        "heading_reversal_samples": heading_reversals,
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


AIRPORTS = {
    "EHAM": (52.3086, 4.7639, "AMS Schiphol"),
    "LIPZ": (45.5053, 12.3519, "VCE Marco Polo"),
}


def summarize(summary: dict, track: list[dict]) -> dict:
    orig = AIRPORTS[summary["orig_icao"]][:2]
    dest = AIRPORTS[summary["dest_icao"]][:2]
    geom = detect_holds_and_deviations(track, orig, dest)
    phases = detect_phases(track)
    go_around = detect_go_around(track, dest)

    takeoff = parse_ts(summary["datetime_takeoff"])
    landing = parse_ts(summary["datetime_landed"])
    block = (landing - takeoff).total_seconds()

    # find time-to-climb to top, max speed, etc
    max_gs = max((p["gspeed"] for p in track), default=0)
    max_alt = max((p["alt"] for p in track), default=0)
    top_of_climb_ts = next((p["timestamp"] for p in track if p["alt"] >= max_alt - 500), None)
    top_of_descent_ts = next((p["timestamp"] for p in reversed(track) if p["alt"] >= max_alt - 500), None)

    return {
        "fr24_id": summary["fr24_id"],
        "flight": summary["flight"],
        "callsign": summary["callsign"],
        "operator": summary["operating_as"],
        "painted_as": summary["painted_as"],
        "aircraft_type": summary["type"],
        "registration": summary["reg"],
        "orig": f'{summary["orig_iata"]} ({summary["orig_icao"]})',
        "dest": f'{summary["dest_iata"]} ({summary["dest_icao"]})',
        "takeoff_utc": summary["datetime_takeoff"],
        "landing_utc": summary["datetime_landed"],
        "runway_takeoff": summary.get("runway_takeoff"),
        "runway_landed": summary.get("runway_landed"),
        "flight_time_s": summary["flight_time"],
        "block_time_s": int(block),
        "actual_distance_km": summary["actual_distance"],
        "circle_distance_km": summary["circle_distance"],
        "max_groundspeed_kt": max_gs,
        "max_altitude_ft": max_alt,
        "top_of_climb_utc": top_of_climb_ts,
        "top_of_descent_utc": top_of_descent_ts,
        "phases_n": len(phases),
        "go_around": go_around,
        **geom,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flight", help="IATA flight number, e.g. U27815")
    ap.add_argument("--date", help="UTC date YYYY-MM-DD")
    ap.add_argument("--fr24-id", help="Fr24 flight id (skip the lookup)")
    ap.add_argument("--out", default=str(DATA_DIR), help="Output dir for raw JSON")
    args = ap.parse_args()

    token = os.environ.get("FR24_TOKEN")
    if not token:
        raise SystemExit("Set FR24_TOKEN env var")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.fr24_id:
        # fetch summary by id by querying a wide window? not directly possible; require flight+date
        raise SystemExit("--fr24-id alone is insufficient; pass --flight and --date too")

    if not (args.flight and args.date):
        ap.error("--flight and --date are required")

    summary = find_flight(token, args.flight, args.date)
    (out / "summary_full.json").write_text(json.dumps({"data": [summary]}, indent=2))
    track = fetch_track(token, summary["fr24_id"])
    (out / "track.json").write_text(json.dumps([{"fr24_id": summary["fr24_id"], "tracks": track}], indent=2))

    report = summarize(summary, track)
    (out / "analysis.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
