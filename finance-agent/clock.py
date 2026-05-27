from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")

_simulated_date: date | None = None


def set_date(d: date | None) -> None:
    global _simulated_date
    _simulated_date = d


def simulated_date() -> date | None:
    return _simulated_date


def is_simulated() -> bool:
    return _simulated_date is not None


def now() -> datetime:
    if _simulated_date is None:
        return datetime.now(timezone.utc)
    close = datetime.combine(_simulated_date, time(16, 0), tzinfo=ET)
    return close.astimezone(timezone.utc)


def today() -> date:
    return now().astimezone(ET).date()


def iso() -> str:
    return now().isoformat()
