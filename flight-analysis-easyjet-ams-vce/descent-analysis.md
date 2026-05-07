# U27815 — Detailed descent and approach analysis

> Drill-down companion to [`report.md`](report.md). Same flight, every
> phase of the descent broken out with timestamps, altitudes, speeds,
> distances and what the data is telling us.

The flight spent **75 minutes** between top of descent and touchdown
— that is more than half of the total block time. Everything after
12:48Z is part of the arrival story, and there is a lot going on.

The full per-30s ASCII profile lives in
[`data/descent_profile.txt`](data/descent_profile.txt). What follows
is the human-language breakdown.

## Top-line numbers

| Anchor | Time (UTC) | Alt | GS | Distance to VCE |
| --- | --- | --- | --- | --- |
| Top of cruise | 12:28:33 | 39,000 ft | 436 kt | ~480 NM |
| Top of descent | 12:48:52 | 38,950 ft | 440 kt | 223 NM |
| First missed-approach minimum | 13:40:02 | **2,700 ft** | 186 kt | **6.77 NM** to RWY04R threshold |
| Hold apex (southernmost point) | 13:52:09 | 6,100 ft | 222 kt | 23 NM south of VCE |
| Touchdown | 14:04:12 | 0 ft | 100 kt | on RWY04R |

The aircraft cruised for **only 21 minutes** at FL390. Top of descent
at 12:48Z was unusually early for a flight that didn't land until
14:04Z — but the descent itself was full of forced level-offs, so
the flying time after TOD ate up the difference.

## Phases of the descent (annotated)

### A. Initial descent (12:48 – 12:51)

Standard "idle descent" out of FL390. About 3 minutes at –900 fpm,
ground speed steady ~420 kt. Nothing remarkable.

### B. **Level-off at FL370** (12:51 – 12:57, 6 min 13 s)

The first sign that the destination was already congested or
weather-impacted. Six minutes of cruising at FL370 is not normal
for a routine descent — it suggests **flow-control by upper-area
ATC**: holding the aircraft high to slow its arrival into the
busier sector below. Ground speed even *increased* slightly from
421 kt to 432 kt while levelled (lower drag at constant power).

### C. Steep step-down to FL290 (12:57 – 13:02)

When ATC released them, the descent was unusually steep — peak
**–2,048 fpm** through FL360 to FL325, then easing to –1,000 fpm.
That kind of step-down is consistent with "expedite descent" because
they had been kept high.

### D. **Level-off at FL290** (13:03 – 13:08, 5 min 28 s)

A second sustained plateau, this time at 29,000 ft. Same story —
flow control by ATC. Ground speed has now decayed to 344 kt as the
aircraft trades altitude for a slower, more aerodynamically stable
arrival profile.

### E. Continuous descent to FL090 (13:08 – 13:27, 19 min)

A textbook continuous descent: from FL290 to ~9,000 ft at a near-
constant –960 to –1,024 fpm and a 3°-equivalent slope. Speed slowly
bleeds from 344 kt to 280 kt. This is the only "happy" 20 minutes
of the descent.

### F. Slam-dunk to 8,000 ft (13:27 – 13:28)

A short, steeper segment at **–1,600 to –1,800 fpm** between FL095
and 8,000 ft. The vertical-speed jump from –1,000 to –1,800 fpm in a
single minute is "expedite to 8,000". By 13:28:50Z the aircraft was
levelling at 8,000 ft.

### G. **Level-off at 8,000 ft** (13:28 – 13:33, 4 min 27 s)

This level segment is **decelerative**: ground speed drops from 287
kt to ~220 kt over four minutes — about 70 kt of speed bled off. At
8,000 ft this almost certainly means flaps came out and the aircraft
configured for terminal arrival. The transponder squawk also changes
to 1000 (Mode-S only / ATC managed) at 13:30 — no special code.

### H. Descent to 6,000 ft platform (13:33 – 13:35)

Brief –1,400 fpm segment from 8,000 to 6,000 ft.

### I. Brief level at 6,100 ft, then final descent (13:35 – 13:39)

The aircraft levels for a minute or two at 6,000–6,100 ft, then
begins the final descent toward the ILS, on track 041° (matching the
runway 04R bearing of 042° magnetic). Ground speed decaying through
243 → 199 kt.

### J. **First ILS approach** (13:36 – 13:39:49)

By 13:38Z the aircraft is on the localizer of ILS RWY 04R (track
041°, on the extended centerline) and descending at –700 to –1,100
fpm. **But it is consistently 500–700 ft above a 3° glideslope**:

| time | distance to threshold | actual alt | 3°-GS alt | delta |
| --- | --- | --- | --- | --- |
| 13:39:26 | 8.54 NM | 3,325 ft | 2,719 ft | **+606 ft** |
| 13:39:34 | 8.06 NM | 3,150 ft | 2,567 ft | +583 ft |
| 13:39:43 | 7.63 NM | 3,000 ft | 2,428 ft | +572 ft |
| 13:39:49 | 7.31 NM | 2,900 ft | 2,327 ft | +573 ft |

Being 500+ ft high, 8 NM out, and decelerating, is **not a stable
ILS profile**. It is more consistent with the crew flying a
"non-standard" descent — possibly a localizer-only or RNAV with
step-down altitudes, or a deliberately-high profile to stay on top
of cell tops in the area. Either way: by all stabilized-approach
criteria (typically: on glideslope, on speed, in landing
configuration by 1,000 ft AGL), this approach was **not stabilized**.

### K. **The vertical-speed disturbance** (13:39:49 – 13:39:58)

This is the heart of the event. Nine seconds of data:

| time | alt (ft) | vs (fpm) | gs (kt) | trk |
| --- | --- | --- | --- | --- |
| 13:39:43 | 3,000 | –1,088 | 186 | 042 |
| 13:39:49 | 2,900 | **+128** | 181 | 040 |
| 13:39:51 | 2,900 | **+576** | 179 | 042 |
| 13:39:53 | 2,925 | –1,088 | 179 | 043 |
| 13:39:56 | 2,850 | **–2,432** | 180 | 042 |
| 13:39:58 | 2,775 | –1,728 | 179 | 041 |
| 13:40:00 | 2,700 | –768 | 180 | 041 |

Vertical speed jumps from –1,088 → +576 (a +1,664 fpm reversal in
6 seconds), then plunges back to **–2,432 fpm in the next 5
seconds**. That is a **~3,000 fpm vertical-speed swing in 7 seconds**,
with ground speed essentially unchanged. The lateral track stays
locked on 041–042° throughout.

A 3,000 fpm reversal is the **classic signature of a microburst /
windshear encounter**: an updraft zone gives way to a downdraft
zone over a few hundred metres of horizontal distance. In a stable
aircraft on autopilot, that is exactly what the trace looks like.

The 13:50Z VCE METAR — issued **9 minutes** after this event —
explicitly reports `WS R04R` (windshear on runway 04R), which would
have been derived in part from preceding aircraft pilot reports
(PIREPs). U27815 was almost certainly *one of those reports*.

### L. **Go-around** (13:40:02 – 13:42:30)

At 13:40:02Z, at 2,700 ft altitude and 6.77 NM from the threshold,
the aircraft initiated a missed approach:

- 13:40:04Z: vs = +576 fpm (climbing)
- 13:40:06Z: vs = +1,280 fpm
- 13:40:13Z: vs = **+2,432 fpm** (TOGA fully applied)
- 13:40:28Z: vs = **+3,072 fpm** (peak rate)
- Speed building from 186 kt to 218 kt to 264 kt
- Track held on **041–042°** — straight along the runway centreline

The aircraft passed **directly over Marco Polo aerodrome** at
13:42:02Z, 5,075 ft, still on track 042° — meaning the missed-
approach procedure was "climb on runway heading", as published for
RWY 04R.

### M. Right turn out, climb to 6,100 ft (13:42:30 – 13:43:15)

The aircraft turned right (track 042° → 083° → 126°) while still
climbing. This puts it on the standard right-turn missed-approach
heading away from the runway and out over the Adriatic / Lagoon.

### N. Holding / radar vectors at 6,100 ft (13:43 – 13:53, ~10 min)

This is **not** a published holding pattern. The geometry shows a
long teardrop:

| time | position | track | distance from VCE |
| --- | --- | --- | --- |
| 13:43 | 6 NM east of field | 126° | 4.5 NM |
| 13:44 | 7 NM SE of field | 192° | 7.3 NM |
| 13:45 | 7 NM south | 224° | 7.6 NM |
| 13:46 | 8 NM south | 180° | 8.3 NM |
| 13:48 | 14 NM south | 167° | 14.7 NM |
| 13:50 | 19 NM south | 246° | 19.0 NM |
| 13:52 | 23 NM SSW | 235° | **23.1 NM** |

A standard ICAO holding pattern has 1-minute (or distance-based)
legs of typically **5–7 NM**. This aircraft flew **~16 NM straight
south** between 13:46 and 13:48 alone, then turned right slowly back
through south-west to west. That is **radar vectoring**, not a
fix-based hold — ATC was actively guiding the aircraft around the
weather while a routing was figured out.

The whole detour at 6,100 ft covers ~46 NM of track — that alone
accounts for about 30 NM of the 148 NM excess vs the great-circle
distance.

### O. Vector to second approach (13:53 – 13:59)

13:53Z onwards the aircraft starts a slow descent from 6,100 ft to
4,650 ft on track 277° (heading west). This is a base-leg vector
positioning the aircraft west of the field for a second approach
to RWY 04R from the south-west.

### P. **Level at 4,100 ft** (13:55 – 13:59, 3 min 38 s)

A brief platform altitude — likely the published intermediate
approach altitude or an ATC-assigned level. Speed steady ~210 kt.

### Q. **Second ILS approach** (13:59 – 14:04)

This time the descent profile is textbook:

| time | distance to threshold | alt | vs |
| --- | --- | --- | --- |
| 14:00:35 | ~9 NM | 2,850 ft | –960 fpm |
| 14:01:08 | ~7 NM | 2,325 ft | –1,408 fpm |
| 14:02:25 | ~3 NM | 1,300 ft | –896 fpm |
| 14:03:00 | ~1.4 NM | 850 ft | –640 fpm |
| 14:03:30 | ~0.5 NM | 450 ft | –768 fpm |
| **14:04:12** | **0** | **0** | touchdown |

Crucially, this approach is **on or just below glideslope** (a 3°
glide at 7 NM gives ~2,210 ft, the aircraft was at 2,325 ft, so
+115 ft — much tighter than the +600 ft of the first attempt). The
speed reduction is monotonic and stabilized: 168 → 142 → 125 → 100
kt at touchdown.

The lat/lon at 14:00:35 (45.392, 12.207) is **the same point**
where the first approach was abandoned 20 minutes earlier — the
aircraft was vectored back to the same approach gate.

### R. Roll-out and taxi (14:04 – 14:05)

Touchdown at 14:04:12Z, weight on wheels (alt = 0). Decelerated
from 100 kt to 50 kt by 14:04:30Z (about 18 seconds of brake-and-
reverse, ~2.7 m/s² average — a brisk but normal landing
deceleration). By 14:05Z the aircraft was at 16 kt, taxiing.

## What this all says

1. **The descent was managed by ATC, not the crew alone.** Two long
   level-offs at FL370 and FL290, and a slam-dunk at the bottom, are
   the classic signature of arrival-flow restriction. The cause was
   developing weather at VCE.
2. **The first approach was high.** 500–700 ft above a 3°
   glideslope at 8 NM — not a stabilized ILS. Whether by procedure
   or by deliberate choice, the aircraft was not on a normal
   precision descent.
3. **The microburst signature is the proximate cause of the
   go-around.** A +1,664 then –3,008 fpm vertical-speed reversal in
   the space of 12 seconds, lateral track unchanged, is what
   windshear looks like in ADS-B data. The METAR confirmed
   `WS R04R` minutes later.
4. **The "hold" wasn't a hold.** It was 10 minutes of radar
   vectoring 23 NM south of the field, around the active cell.
5. **The second approach was textbook.** Stable on glideslope, on
   speed, monotonic deceleration to touchdown.
6. **The crew got the timing exactly right.** 16 minutes after
   landing, the airport was reporting +TSRA, vis 1,200 m, gusts
   23 kt, CB at 800 ft. They landed in a brief lull between cells.

## Caveats again

- All altitudes are pressure altitude as reported on ADS-B (Mode S).
- Vertical speed is FR24-derived and can be noisy at the per-sample
  level, but trends across multiple samples are robust.
- Distance-to-threshold uses an approximated 04R threshold of
  (45.4806, 12.3199); the published AIP coordinates would shift this
  by tens of metres at most.
- "Microburst signature" is a structural inference from the data
  pattern, not a confirmed report. We can't see what the on-board
  predictive windshear system did or what the crew briefed; only
  what the aircraft physically did. The aircraft physics + the
  contemporaneous METAR `WS R04R` are highly consistent with that
  reading.
