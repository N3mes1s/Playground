# flight-analysis-easyjet-ams-vce

Reconstruct what happened on a single commercial flight using the
[Flightradar24 API](https://fr24api.flightradar24.com/) cross-referenced with
METAR observations from `aviationweather.gov`.

Case study: **easyJet U27815, AMS → VCE, 6 May 2026** — see
[`report.md`](report.md).

## Layout

| File | Role |
| --- | --- |
| `fr24_analyze.py` | Resolves a flight number on a date to an FR24 record, fetches the full track, runs phase / level-off / go-around / lateral-deviation detection. |
| `weather.py` | Pulls METARs for two ICAOs (last 48 h window) and parses out wind, visibility and significant phenomena (TS, CB, WS, etc). |
| `correlate.py` | Joins the FR24 track to the METAR timeline and produces a stdout report plus `data/timeline.json`. |
| `report.md` | Human-readable narrative for U27815. |
| `data/` | Raw API responses + derived JSON. Not committed (see `.gitignore`). |

## Running

```bash
export FR24_TOKEN="<your fr24 api token>"
python3 fr24_analyze.py --flight U27815 --date 2026-05-06
python3 weather.py
python3 correlate.py
```

Standard library only — no `pip install` required.

## Method

1. **Find the flight.** `GET /api/flight-summary/full` filtered by
   `flight_datetime_from`/`flight_datetime_to` and `flights=` resolves the
   IATA flight number on a UTC date to a single `fr24_id`. Note that EZY
   metal often operates as `EJU` (easyJet Europe), so filtering by
   `operating_as=EZY` will miss them — match by callsign / `painted_as`
   instead, or just by route.
2. **Fetch the track.** `GET /api/flight-tracks?flight_id=…` returns up to
   ~1k position samples (lat, lon, alt, ground-speed, vertical-speed,
   track, squawk, source) at irregular but ~few-second cadence.
3. **Detect anomalies.**
   - *Phases* by altitude/vspeed thresholds (climb / cruise / descent /
     ground).
   - *Level-offs* in descent (segments where |vspeed| < 100 fpm above 5,000
     ft for ≥ 60 s and the segment altitude is at least 2,000 ft below the
     observed cruise ceiling) — a proxy for ATC step-down vectors or holds.
   - *Lateral deviation*: total flown distance vs origin–destination
     great-circle, plus pointwise excess (origin→p + p→destination − GC).
   - *Go-around*: any sustained ≥ +1,500 fpm climb starting below 3,500 ft
     within 15 NM of the destination.
4. **Cross-reference with METARs.** `aviationweather.gov/api/data/metar`
   (no auth, last 48 h). For each significant flight event we pick the
   most recent METAR at-or-before the event time at the relevant airport.
5. **Tell the story.** `correlate.py` prints a narrative; `report.md`
   spells out the findings for human readers.

## Why these signals matter

- A **go-around** is the strongest single anomaly you can detect from
  ADS-B alone — it implies the crew judged the approach unsafe to
  continue, or were instructed to discontinue. Pair it with the METAR
  in force at that moment and you usually have your "why".
- **Step level-offs in descent** at high altitudes correlate with
  ATC traffic-flow management; clusters of short level-offs in the
  terminal area correlate with vectoring for spacing or weather.
- **Excess track distance** vs great-circle is dominated on short hauls
  by terminal procedures (SID/STAR), but anomalies above ~20 % are
  worth investigating for weather routing or military airspace.
- **METAR significant phenomena** (TS, CB, VCTS, WS, TEMPO TSRA, +TSRA,
  FZRA, FG with vis < 1000m, etc.) explain the great majority of
  approach-phase anomalies into European hubs.

## Limitations

- ADS-B coverage gaps can produce phantom "level-offs" or missing
  segments. We don't smooth or interpolate.
- The METAR endpoint here serves the most recent 48 h — for older
  flights you'll need a different source (e.g. NOAA's archive).
- The go-around detector is opportunistic; it doesn't distinguish a
  true missed-approach from a low-altitude vector if the climb is
  steep enough.
- Great-circle vs flown distance is a blunt instrument — required SID/
  STAR routing is "deviation" by this measure.
