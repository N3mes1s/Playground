"""METAR fetch + minimal parse for cross-reference with flight events.

Source: aviationweather.gov public API (no auth, last 48h window).
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def fetch_metars(icaos: list[str], hours: int = 48) -> list[dict]:
    qs = urllib.parse.urlencode({"ids": ",".join(icaos), "format": "json", "hours": hours})
    url = f"https://aviationweather.gov/api/data/metar?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "playground-flight-analyzer/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


# Phenomena worth flagging in an aviation context
SIGNIFICANT_TOKENS = {
    "TS": "thunderstorm",
    "TSRA": "thunderstorm with rain",
    "+TSRA": "heavy thunderstorm with rain",
    "VCTS": "thunderstorm in vicinity",
    "CB": "cumulonimbus",
    "TCU": "towering cumulus",
    "WS": "windshear",
    "FG": "fog",
    "BR": "mist",
    "FZRA": "freezing rain",
    "SN": "snow",
    "GR": "hail",
    "SQ": "squall",
    "FC": "funnel cloud",
}


def flag_metar(raw: str) -> list[str]:
    flags = []
    tokens = raw.split()
    for tok in tokens:
        # exact CB/TCU on cloud-layer tokens (e.g. FEW010CB)
        if tok.endswith("CB"):
            flags.append("cumulonimbus")
        if tok.endswith("TCU"):
            flags.append("towering cumulus")
        if tok in SIGNIFICANT_TOKENS:
            flags.append(SIGNIFICANT_TOKENS[tok])
    if "TEMPO TSRA" in raw or re.search(r"TEMPO[^=]*TSRA", raw):
        flags.append("temporary thunderstorm with rain forecast")
    if re.search(r"\bWS\s+R\d", raw):
        flags.append("runway windshear")
    if re.search(r"\bVCTS\b", raw):
        flags.append("thunderstorm in vicinity")
    return sorted(set(flags))


def vis_meters(raw: str) -> int | None:
    """Crude visibility extractor: the 4-digit group right after wind."""
    m = re.search(r"\d{3}\d{2}(?:G\d+)?KT(?:\s+\d{3}V\d{3})?\s+(\d{4})\b", raw)
    if m:
        return int(m.group(1))
    if "CAVOK" in raw:
        return 9999
    return None


def wind_from(raw: str) -> tuple[int | None, int | None, int | None]:
    """(direction_deg, speed_kt, gust_kt) parsed from the wind group."""
    m = re.search(r"\b(VRB|\d{3})(\d{2,3})(?:G(\d{2,3}))?KT\b", raw)
    if not m:
        return (None, None, None)
    d = None if m.group(1) == "VRB" else int(m.group(1))
    return (d, int(m.group(2)), int(m.group(3)) if m.group(3) else None)


def filter_window(metars: list[dict], icao: str, start: datetime, end: datetime) -> list[dict]:
    out = []
    for m in metars:
        if m["icaoId"] != icao:
            continue
        rt = datetime.fromisoformat(m["reportTime"].replace("Z", "+00:00"))
        if start <= rt <= end:
            out.append(m)
    return sorted(out, key=lambda x: x["reportTime"])


def annotate(metars: list[dict]) -> list[dict]:
    out = []
    for m in metars:
        d, s, g = wind_from(m["rawOb"])
        out.append({
            "time": m["reportTime"],
            "icao": m["icaoId"],
            "wind_dir": d,
            "wind_kt": s,
            "gust_kt": g,
            "visib_m": vis_meters(m["rawOb"]),
            "flags": flag_metar(m["rawOb"]),
            "raw": m["rawOb"],
        })
    return out


def main() -> None:
    metars = fetch_metars(["EHAM", "LIPZ"], hours=48)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "metars.json").write_text(json.dumps(metars, indent=2))
    print(f"saved {len(metars)} METARs to {DATA_DIR/'metars.json'}")


if __name__ == "__main__":
    main()
