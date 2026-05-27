import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import config


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    return obj


def append(kind: str, payload: dict) -> None:
    entry = {"t": _now(), "kind": kind, **_serialize(payload)}
    with config.JOURNAL_PATH.open("a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def read_since(days: int) -> list[dict]:
    if not config.JOURNAL_PATH.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    with config.JOURNAL_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                t = datetime.fromisoformat(entry["t"])
                if t >= cutoff:
                    out.append(entry)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    return out
