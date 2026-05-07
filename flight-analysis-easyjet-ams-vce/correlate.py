"""Cross-reference flight events with METAR observations.

Reads data/summary_full.json, data/track.json, data/metars.json (already saved
by fr24_analyze.py and weather.py) and emits data/timeline.json + a stdout
report a human can read.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fr24_analyze import detect_holds_and_deviations, AIRPORTS, parse_ts, summarize
from weather import annotate, filter_window

DATA_DIR = Path(__file__).parent / "data"


def latest_metar_at_or_before(metars: list[dict], when: datetime) -> dict | None:
    candidates = [m for m in metars if datetime.fromisoformat(m["time"].replace("Z","+00:00")) <= when]
    return candidates[-1] if candidates else None


def fmt_metar(m: dict) -> str:
    flags = ", ".join(m["flags"]) if m["flags"] else "no significant phenomena"
    return f"  {m['time']} {m['icao']}  | {flags}\n    {m['raw']}"


def main() -> None:
    summary = json.loads((DATA_DIR / "summary_full.json").read_text())["data"][0]
    track = json.loads((DATA_DIR / "track.json").read_text())[0]["tracks"]
    metars_raw = json.loads((DATA_DIR / "metars.json").read_text())

    takeoff = parse_ts(summary["datetime_takeoff"])
    landing = parse_ts(summary["datetime_landed"])
    window_start = takeoff - timedelta(hours=2)
    window_end = landing + timedelta(hours=2)

    ams = annotate(filter_window(metars_raw, "EHAM", window_start, window_end))
    vce = annotate(filter_window(metars_raw, "LIPZ", window_start, window_end))

    rep = summarize(summary, track)

    # Build narrative timeline
    print("=" * 78)
    print(f"Flight {summary['flight']} ({summary['callsign']})  {summary['orig_iata']} -> {summary['dest_iata']}")
    print(f"Aircraft: {summary['type']} reg {summary['reg']} (operated by {summary['operating_as']})")
    print(f"Block: {takeoff.isoformat()} -> {landing.isoformat()}  ({rep['flight_time_s']//60} min)")
    print(f"Distance: flown {rep['flown_nm']} NM vs great-circle {rep['great_circle_nm']} NM "
          f"(+{rep['excess_nm']} NM, {round(100*rep['excess_nm']/rep['great_circle_nm'],1)}%)")
    print(f"Max alt: {rep['max_alt_ft']} ft   Max GS: {rep['max_groundspeed_kt']} kt")
    print()

    print("--- AMS (EHAM) METARs in window ---")
    for m in ams:
        print(fmt_metar(m))

    print("\n--- VCE (LIPZ) METARs in window ---")
    for m in vce:
        print(fmt_metar(m))

    # Departure conditions
    print("\n--- Departure conditions @ AMS ---")
    dep = latest_metar_at_or_before(ams, takeoff)
    if dep:
        print(fmt_metar(dep))

    # Arrival conditions: nearest METAR before top-of-descent and during approach
    tod = parse_ts(rep["top_of_descent_utc"])
    print("\n--- Arrival environment @ VCE ---")
    for label, t in [("at top of descent", tod), ("at landing", landing)]:
        m = latest_metar_at_or_before(vce, t)
        if m:
            print(f"\n  {label} ({t.isoformat()}):")
            print(fmt_metar(m))

    # Level-offs in descent / hold-equivalent
    print("\n--- Level-offs detected during cruise/descent ---")
    if rep["level_offs"]:
        for lo in rep["level_offs"]:
            print(f"  {lo['start']} -> {lo['end']}  alt {lo['alt']} ft  ({lo['duration_s']} s)")
    else:
        print("  none")

    # Save unified timeline
    timeline = {
        "flight": rep,
        "ams_metars": ams,
        "vce_metars": vce,
        "departure_metar": dep,
        "arrival_top_of_descent_metar": latest_metar_at_or_before(vce, tod),
        "landing_metar": latest_metar_at_or_before(vce, landing),
    }
    (DATA_DIR / "timeline.json").write_text(json.dumps(timeline, indent=2))
    print(f"\nsaved {DATA_DIR/'timeline.json'}")


if __name__ == "__main__":
    main()
