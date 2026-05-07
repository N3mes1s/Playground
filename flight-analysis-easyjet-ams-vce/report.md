# U27815 — easyJet AMS → VCE — 6 May 2026

> **Headline:** the flight executed a go-around at Venice on its first ILS
> approach to runway 04R because the airport had just gone convective with
> reported windshear on that runway. After ~10 minutes orbiting at 6,100 ft
> the crew flew a successful second approach and landed in a brief lull
> 16 minutes before the heaviest +TSRA cell arrived.

## Flight identity

| field | value |
| --- | --- |
| Flight | U27815 (callsign EJU52UQ) |
| Operator | easyJet Europe (EJU), painted as easyJet (EZY) |
| Aircraft | Airbus A320neo, reg **OE-LSM** |
| FR24 ID | `3f902a0d` |
| Route | AMS (EHAM) → VCE (LIPZ) |
| Off-block / takeoff | 2026-05-06 12:05:39 UTC, runway 09 |
| Touchdown / on-block | 2026-05-06 14:04:38 UTC, runway 04R |
| Block time | 1 h 59 min |
| Distance flown | **654.1 NM** (vs 505.9 NM great-circle, **+148 NM / +29%**) |

## Timeline (UTC)

| Time | Event | Source |
| --- | --- | --- |
| 12:05:39 | Takeoff EHAM rwy 09, calm conditions (`06014KT 9999 NOSIG`) | FR24 + EHAM 11:55Z METAR |
| 12:27:00 | Top of climb FL390 | track |
| 12:48:52 | Top of descent — only **21 min in cruise** | track |
| 12:50:00 | LIPZ METAR: `…BKN070 18/16 Q1010 **TEMPO TSRA**` (thunderstorm forecast) | METAR |
| 12:51 – 12:57 | Step-level at FL370 (6 min 13 s) | track |
| 13:03 – 13:08 | Step-level at FL290 (4 min 36 s combined) | track |
| 13:20:00 | LIPZ METAR: TEMPO TSRA still active | METAR |
| 13:36 – 13:40 | **First ILS approach** to RWY04R, descending on track 041° | track |
| **13:40:00** | **Go-around** — minimum alt **2,700 ft** at **7.86 NM** from 04R threshold; +2,400 fpm climb commanded, peak +3,072 fpm | **track** |
| 13:43 – 13:51 | Holding at **6,100 ft** SSW of the field, four discrete level segments (cumulative ~6.5 min level + heading reversals) | track |
| 13:50:00 | LIPZ METAR (issued mid-orbit): `**VCTS** FEW010**CB** BKN040 17/16 Q1009 **WS R04R** TEMPO 3000 TSRA` | METAR |
| 13:54 – 14:00 | Re-position SW of field, then turn back to final | track |
| 14:00:35 | Second approach commences from 2,850 ft on track 041° (same gate as the aborted approach) | track |
| **14:04:12** | **Touchdown** rwy 04R | track |
| 14:04:32 | Reaches LIPZ aerodrome reference point (45.5053, 12.3520) | track |
| 14:20:00 | LIPZ METAR (16 min after landing): `19010**G23**KT 130V230 **1200** R04R/1600D **+TSRA** **BKN008CB** 14/14 Q1009 **WS R04R**` — heavy thunderstorm, vis 1.2 km, gusts 23 kt | METAR |
| 14:50:00 | LIPZ METAR: `RETSRA NOSIG` (recent thunderstorm with rain, conditions improving) | METAR |

## What actually happened

### 1. Departure was uneventful

Schiphol at 12:00Z had a NE wind 060°/14 kt, unlimited visibility,
some scattered cloud at 4,100 ft, NOSIG. Runway 09 (heading 086°) was
into-wind. Nothing in the EHAM data hints at a delay or anomaly.

### 2. Routing through central Europe was longer than the great-circle

Total flown 654.1 NM versus 505.9 NM direct — a **29 % overflight**.
Maximum lateral excess (sum of orig→here + here→dest minus the great-
circle) reached **40.9 NM at 13:52Z**, but this point is *during the
hold near VCE*, not the en-route portion. The en-route excess is mostly
a function of standard airway routing across the Alps and central
Italy. The descent profile, however, is unusual: top-of-descent is
12:48Z, only 21 min after top-of-climb, and there are step level-offs
at FL370 and FL290 — consistent with ATC traffic-flow restrictions
into a deteriorating destination.

### 3. The smoking gun is at Venice

Until 12:20Z, LIPZ was reporting light rain (`-RA`) under broken cloud
at 7,000 ft and a 150°/4–7 kt wind. From the **12:50Z** METAR onwards,
the report carries `TEMPO TSRA` — an aerodrome thunderstorm warning.
That is the picture the crew of U27815 had through the descent.

### 4. The first approach was discontinued

Track points show a textbook ILS-style descent on heading 041° (runway
04R is 042°) from FL050 down to **2,700 ft at 7.86 NM** from the
threshold (about 350 ft AGL above where you'd expect to be on a 3°
glidepath at that range — i.e. the aircraft was either still high or
had just passed the FAF and was levelling). Then within four
seconds the vertical-speed flips from –1,728 fpm to +1,728 fpm,
ramping to **+3,072 fpm** by 13:40:37Z — a TOGA-thrust missed
approach. The pilots climbed straight ahead on the runway centreline
out to ~13 NM, then turned right.

### 5. The 13:50Z METAR explains why

Issued *during* the orbit, `VCTS FEW010CB BKN040 ... WS R04R` declared:

- thunderstorm in vicinity
- cumulonimbus at 1,000 ft AGL
- **windshear on runway 04R** (the runway being used)

A windshear alert on the approach runway — whether reported by tower,
preceding traffic, or the aircraft's own predictive windshear system —
is a prima-facie reason to discontinue the approach. The track is
fully consistent with that.

### 6. The orbit at 6,100 ft

Between 13:43Z and 13:51Z the aircraft made four level segments at
6,100 ft with track changing from 041° → 128° → 219° → 277° —
roughly a tear-drop / racetrack pattern south of the field. This is
either a published hold or radar vectors for spacing. Net result:
~10 min of holding before the second approach.

### 7. The second approach succeeded

At 14:00:35Z the aircraft passes through 2,850 ft at lat/lon
45.39, 12.21 — the **same point** where it had aborted 20 minutes
earlier. From here the descent is continuous and stable to a touchdown
at 14:04:12Z (alt → 0, gs decaying from 100 → 0 kt).

### 8. Lucky timing

The 14:20Z METAR — issued 16 minutes after landing — is dramatic:

```
LIPZ 061420Z 19010G23KT 130V230 1200 R04R/1600D +TSRA BKN008CB 14/14 Q1009 WS R04R BECMG 6000 NSW
```

Visibility collapsed from 9999 m to **1,200 m**, runway visual range
on 04R was decreasing through 1,600 m, wind shifted by 60° and gusted
23 kt, and the rain went from "in vicinity" to **heavy thunderstorm at
the field**. Cumulonimbus base dropped from 1,000 ft to **800 ft**.

In short: U27815 squeezed onto runway 04R between two cells. The first
approach was inside the leading edge of the storm (windshear reported,
go-around required); the second approach made it down before the core
of the cell hit Marco Polo.

## Caveats and limitations

- Position data is ADS-B; vertical speed is the FR24-derived value.
- "Block time" here is takeoff-to-landing; gate-to-gate timing isn't in
  the FR24 summary endpoint used.
- The "great-circle excess" metric uses straight-line haversine and
  does not account for required terminal-area procedures (SIDs/STARs)
  which legitimately add miles even on an uneventful flight.
- The go-around heuristic in `fr24_analyze.py` flags any climb of
  ≥ +1,500 fpm sustained from below 3,500 ft within 15 NM of the
  destination. It is opportunistic, not certified.
- METARs are taken from `aviationweather.gov` (NWS/NOAA mirror of the
  ICAO global feed) and represent the airport's own observations.

## Reproduce

```bash
export FR24_TOKEN="…"
python fr24_analyze.py --flight U27815 --date 2026-05-06
python weather.py
python correlate.py
```

Raw artefacts land in `data/`:
`summary_full.json`, `track.json`, `metars.json`, `analysis.json`, `timeline.json`.
