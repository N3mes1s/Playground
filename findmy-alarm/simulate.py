"""Simulated Find My source -- exercise the whole alarm with no Apple account.

Why this exists: the alarm is only useful once it runs unattended for days, and
the parts that are easy to get wrong (geofence edges, SMTP config, systemd
wiring) have nothing to do with Apple. This module fakes the *only* thing that
needs Apple -- a decrypted location report -- so the real code path
(fetch -> geofence -> notify) can be run and verified anywhere, by anyone,
without a login, without a tag, and without handing your keys to a machine you
don't control.

Use it to:
  * smoke-test your SMTP setup before arming the real thing
  * watch a departure alarm fire on demand instead of waiting for a thief
  * develop/CI the tool with no credentials in the environment

    python findmy_alarm.py watch --email you@gmail.com --simulate --radius 100
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# One degree of latitude is ~111 km; used to turn "meters away" into coordinates.
_M_PER_DEG_LAT = 111_000.0


@dataclass
class SimulatedReport:
    """Duck-typed stand-in for FindMy.py's LocationReport."""

    latitude: float
    longitude: float
    horizontal_accuracy: int
    timestamp: datetime

    def __str__(self) -> str:  # mirrors LocationReport's printable form
        return (
            f"SimulatedReport({self.latitude:.6f}, {self.longitude:.6f}, "
            f"±{self.horizontal_accuracy}m @ {self.timestamp.isoformat()})"
        )


@dataclass
class SimulatedAccount:
    """Stands in for AppleAccount, replaying a scripted track per object.

    The track is deliberately boring-then-alarming: the object sits at the
    anchor for ``dwell_polls`` fetches (so you see it arm), then walks away in
    ``step_m`` increments (so you see exactly one departure alarm, then silence
    unless you enabled renotify).
    """

    lat: float = 45.4642           # default: Milan, arbitrary
    lon: float = 9.1900
    dwell_polls: int = 2
    step_m: float = 120.0
    accuracy_m: int = 12
    _counts: dict = field(default_factory=dict)

    def fetch_location(self, source):
        """``source`` is the object's name here -- one track per object."""
        n = self._counts.get(source, 0)
        self._counts[source] = n + 1

        if n < self.dwell_polls:
            meters_away = 0.0
        else:
            meters_away = (n - self.dwell_polls + 1) * self.step_m

        return SimulatedReport(
            latitude=self.lat + (meters_away / _M_PER_DEG_LAT),
            longitude=self.lon,
            horizontal_accuracy=self.accuracy_m,
            timestamp=datetime.now(timezone.utc) + timedelta(seconds=n),
        )

    # The watch loop persists the session after each round; nothing to do here.
    def to_json(self, path: str) -> None:  # noqa: D102 - interface parity
        return None


def simulated_source(obj) -> str:
    """Key the simulated track by object name instead of reading a .plist."""
    return obj.name


def build_simulated_account(anchor: Optional[dict] = None, **kwargs) -> SimulatedAccount:
    """Construct the fake account, optionally starting from a given anchor."""
    if anchor:
        kwargs.setdefault("lat", float(anchor["lat"]))
        kwargs.setdefault("lon", float(anchor["lon"]))
    return SimulatedAccount(**kwargs)
