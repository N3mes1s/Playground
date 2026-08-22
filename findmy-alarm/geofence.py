"""Geofence math and edge-triggered alarm state.

A geofence is an anchor point (lat/lon) plus a radius in meters. The object is
"inside" while it stays within the radius and "outside" once it crosses it.
The alarm fires on the inside->outside transition (like arming a real alarm),
not on every poll, so you get one alert when the thing starts moving rather
than a stream of them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

# Mean Earth radius (meters). Good enough for geofences of a few km.
_EARTH_RADIUS_M = 6_371_000.0


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in meters."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * _EARTH_RADIUS_M * math.asin(math.sqrt(a))


@dataclass
class Anchor:
    """The "home" location the object is expected to stay near."""

    lat: float
    lon: float

    @classmethod
    def from_dict(cls, d: dict) -> "Anchor":
        return cls(lat=float(d["lat"]), lon=float(d["lon"]))

    def to_dict(self) -> dict:
        return {"lat": self.lat, "lon": self.lon}


@dataclass
class GeofenceState:
    """Persistent per-object state for the alarm.

    ``inside`` tracks which side of the fence we last saw the object on, so we
    can fire only on transitions. ``anchor`` may be captured automatically on
    the first successful fetch when the user didn't supply one.
    """

    anchor: Optional[Anchor] = None
    inside: Optional[bool] = None  # None == unknown / not yet observed
    last_alarm_ts: float = 0.0
    last_distance_m: Optional[float] = None

    @classmethod
    def from_dict(cls, d: dict) -> "GeofenceState":
        anchor = d.get("anchor")
        return cls(
            anchor=Anchor.from_dict(anchor) if anchor else None,
            inside=d.get("inside"),
            last_alarm_ts=float(d.get("last_alarm_ts", 0.0)),
            last_distance_m=d.get("last_distance_m"),
        )

    def to_dict(self) -> dict:
        return {
            "anchor": self.anchor.to_dict() if self.anchor else None,
            "inside": self.inside,
            "last_alarm_ts": self.last_alarm_ts,
            "last_distance_m": self.last_distance_m,
        }


@dataclass
class Evaluation:
    """Result of comparing one fetched location against the geofence."""

    distance_m: float
    outside: bool
    should_alarm: bool
    anchor_captured: bool = False
    kind: str = "position"  # "position" | "departure" | "still_away"


def evaluate(
    state: GeofenceState,
    lat: float,
    lon: float,
    radius_m: float,
    now: float,
    renotify_after_s: float = 0.0,
) -> Evaluation:
    """Update ``state`` with a new fix and decide whether to raise the alarm.

    Mutates ``state`` in place (side, distance, alarm timestamp) and returns an
    :class:`Evaluation` describing what happened.

    * If no anchor is set yet, the first fix becomes the anchor and the object
      is considered inside (armed) -- no alarm.
    * The alarm fires on an inside->outside transition.
    * If ``renotify_after_s`` > 0, a re-alert fires while the object stays
      outside and that many seconds have passed since the last alarm.
    """
    anchor_captured = False
    if state.anchor is None:
        state.anchor = Anchor(lat=lat, lon=lon)
        state.inside = True
        state.last_distance_m = 0.0
        anchor_captured = True
        return Evaluation(
            distance_m=0.0,
            outside=False,
            should_alarm=False,
            anchor_captured=True,
            kind="position",
        )

    distance = haversine_m(state.anchor.lat, state.anchor.lon, lat, lon)
    outside = distance > radius_m
    was_inside = state.inside is not False  # treat unknown as "was inside"

    should_alarm = False
    kind = "position"
    if outside and was_inside:
        # Crossed the fence: this is the primary departure alarm.
        should_alarm = True
        kind = "departure"
        state.last_alarm_ts = now
    elif outside and not was_inside:
        # Still away -- optionally remind on a cooldown.
        if renotify_after_s > 0 and (now - state.last_alarm_ts) >= renotify_after_s:
            should_alarm = True
            kind = "still_away"
            state.last_alarm_ts = now

    state.inside = not outside
    state.last_distance_m = distance
    return Evaluation(
        distance_m=distance,
        outside=outside,
        should_alarm=should_alarm,
        anchor_captured=anchor_captured,
        kind=kind,
    )
