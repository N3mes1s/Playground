"""Render an ASCII altitude / vertical-speed profile of the descent phase.

Reads data/track.json and prints to stdout. Helps eyeball where the
step-downs, the go-around, and the second approach were.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main() -> None:
    track = json.loads((DATA_DIR / "track.json").read_text())[0]["tracks"]

    # focus window: top of descent to landing
    tod = datetime(2026, 5, 6, 12, 45, tzinfo=timezone.utc)
    end = datetime(2026, 5, 6, 14, 5, tzinfo=timezone.utc)
    desc = [p for p in track if tod <= parse_ts(p["timestamp"]) <= end]

    # bin to 30-second buckets
    buckets: dict[int, list[dict]] = {}
    for p in desc:
        ts = parse_ts(p["timestamp"])
        key = int((ts - tod).total_seconds() // 30)
        buckets.setdefault(key, []).append(p)

    rows = sorted(buckets.items())

    max_alt = max(p["alt"] for p in desc)
    width = 70  # columns

    print(f"\nAltitude profile  ({tod.strftime('%H:%M')}Z -> {end.strftime('%H:%M')}Z)\n")
    print(f"  ground -> FL{max_alt//100:03d}  width = {width} cols, each col = {max_alt/width:.0f} ft\n")
    print("  time   alt(ft)   vs(fpm)  gs(kt)  |" + "altitude bar".ljust(width) + "|")
    print("  -----  --------  -------  ------  +" + "-" * width + "+")
    for k, pts in rows:
        ts = tod + timedelta(seconds=30 * k)
        alts = [p["alt"] for p in pts]
        vss = [p["vspeed"] for p in pts]
        gss = [p["gspeed"] for p in pts]
        alt = sum(alts) / len(alts)
        vs = sum(vss) / len(vss)
        gs = sum(gss) / len(gss)
        bar = int(round(alt / max_alt * width))
        # vertical-speed marker
        if vs > 1500: char = "^"
        elif vs > 500: char = "/"
        elif vs < -1500: char = "v"
        elif vs < -500: char = "\\"
        else: char = "="
        line = (char * bar).ljust(width)
        print(f"  {ts.strftime('%H:%M')}  {int(alt):8d}  {int(vs):+7d}  {int(gs):6d}  |{line}|")


if __name__ == "__main__":
    main()
