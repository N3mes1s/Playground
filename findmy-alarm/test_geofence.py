"""Offline tests for the geofence/alarm logic -- no Apple account needed.

Run: python test_geofence.py
"""

from geofence import GeofenceState, evaluate, haversine_m


def approx(a, b, tol):
    return abs(a - b) <= tol


def test_haversine_known_distance():
    # ~1 degree of latitude is ~111 km.
    d = haversine_m(45.0, 9.0, 46.0, 9.0)
    assert approx(d, 111_000, 2_000), d


def test_first_fix_captures_anchor_no_alarm():
    st = GeofenceState()
    ev = evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)
    assert ev.anchor_captured is True
    assert ev.should_alarm is False
    assert st.anchor is not None
    assert st.inside is True


def test_stays_inside_no_alarm():
    st = GeofenceState()
    evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)  # anchor
    # ~15 m away, inside a 100 m fence.
    ev = evaluate(st, 45.0001, 9.0001, radius_m=100, now=1100.0)
    assert ev.outside is False
    assert ev.should_alarm is False


def test_departure_triggers_alarm_once():
    st = GeofenceState()
    evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)  # anchor
    # ~1.1 km away -> outside.
    ev = evaluate(st, 45.01, 9.0, radius_m=100, now=1100.0)
    assert ev.outside is True
    assert ev.should_alarm is True
    assert ev.kind == "departure"
    # Still outside on next poll -> no repeat alarm (renotify off).
    ev2 = evaluate(st, 45.01, 9.0, radius_m=100, now=1200.0)
    assert ev2.outside is True
    assert ev2.should_alarm is False


def test_renotify_while_away():
    st = GeofenceState()
    evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)
    evaluate(st, 45.01, 9.0, radius_m=100, now=1100.0)  # departure alarm
    # 30 s later, renotify window is 60 s -> no alert yet.
    ev = evaluate(st, 45.01, 9.0, radius_m=100, now=1130.0, renotify_after_s=60)
    assert ev.should_alarm is False
    # 90 s after last alarm -> re-alert.
    ev2 = evaluate(st, 45.01, 9.0, radius_m=100, now=1190.0, renotify_after_s=60)
    assert ev2.should_alarm is True
    assert ev2.kind == "still_away"


def test_return_rearms():
    st = GeofenceState()
    evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)
    evaluate(st, 45.01, 9.0, radius_m=100, now=1100.0)  # departure
    evaluate(st, 45.0, 9.0, radius_m=100, now=1200.0)   # back inside
    assert st.inside is True
    # Leaves again -> fresh departure alarm.
    ev = evaluate(st, 45.01, 9.0, radius_m=100, now=1300.0)
    assert ev.should_alarm is True
    assert ev.kind == "departure"


def test_serialization_roundtrip():
    st = GeofenceState()
    evaluate(st, 45.0, 9.0, radius_m=100, now=1000.0)
    restored = GeofenceState.from_dict(st.to_dict())
    assert restored.anchor.lat == st.anchor.lat
    assert restored.inside == st.inside


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
