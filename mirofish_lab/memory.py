"""Local, JSON-backed memory. Replaces the Zep Cloud dependency MiroFish uses.

Two scopes:
- Session memory: in-process list, lost on exit. Default for bounded sims.
- Persistent memory: append-only JSONL per agent name, lives under MIROFISH_MEMORY_DIR.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class MemoryRecord:
    role: str
    content: str
    ts: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content, "ts": self.ts, "tags": self.tags}

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryRecord":
        return cls(role=d["role"], content=d["content"], ts=d.get("ts", 0.0), tags=d.get("tags", []))


class LocalMemory:
    """Per-agent memory log. Persists to a JSONL file if root dir is provided."""

    def __init__(self, agent_name: str, root: Path | None = None):
        self.agent_name = agent_name
        self.root = root
        self._records: list[MemoryRecord] = []
        if self.root is not None:
            self.root.mkdir(parents=True, exist_ok=True)
            self._load()

    @property
    def _path(self) -> Path | None:
        if self.root is None:
            return None
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.agent_name)
        return self.root / f"{safe}.jsonl"

    def _load(self) -> None:
        p = self._path
        if p is None or not p.exists():
            return
        with p.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._records.append(MemoryRecord.from_dict(json.loads(line)))
                except json.JSONDecodeError:
                    continue

    def add(self, role: str, content: str, tags: Iterable[str] = ()) -> None:
        rec = MemoryRecord(role=role, content=content, tags=list(tags))
        self._records.append(rec)
        p = self._path
        if p is not None:
            with p.open("a") as f:
                f.write(json.dumps(rec.to_dict()) + "\n")

    def all(self) -> list[MemoryRecord]:
        return list(self._records)

    def recent(self, n: int) -> list[MemoryRecord]:
        return self._records[-n:]

    def filter_tag(self, tag: str) -> list[MemoryRecord]:
        return [r for r in self._records if tag in r.tags]

    def to_chat_messages(self) -> list[dict]:
        """Render memory as OpenAI-style chat messages (role, content)."""
        return [{"role": r.role, "content": r.content} for r in self._records]

    def clear(self) -> None:
        self._records.clear()
        p = self._path
        if p is not None and p.exists():
            p.unlink()
