"""
Content-addressable build cache — the "make" in llmake.

Each target's artifact is keyed by a hash over everything that can change its
output: the fully-rendered prompt, the provider, the model, the params, and
(transitively) its upstream artifacts. If the key matches the last build and
the artifact file still exists, the target is up to date and is skipped. This
gives incremental, reproducible builds: change one note, and only the targets
downstream of it recompute.

The cache index is a small JSON file under ``.llmake/cache.json`` and is safe
to commit (it makes builds reproducible across machines) or to .gitignore.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Entry:
    key: str                       # the cache key (content hash)
    artifact: str                  # artifact path, relative to workspace root
    provider: str = ""
    model: str = ""
    kind: str = ""
    created: str = ""              # ISO timestamp
    inputs: list = field(default_factory=list)
    needs: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def compute_key(
    *,
    prompt: str,
    provider: str,
    model: str,
    kind: str,
    params: dict,
    upstream_keys: list,
) -> str:
    """Deterministic cache key for a target build."""
    payload = json.dumps(
        {
            "prompt": prompt,
            "provider": provider,
            "model": model,
            "kind": kind,
            "params": params,
            "upstream": sorted(upstream_keys),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Cache:
    """The on-disk build index."""

    def __init__(self, path: Path):
        self.path = path
        self.entries: dict[str, Entry] = {}
        self._load()

    def _load(self) -> None:
        if self.path.is_file():
            raw = json.loads(self.path.read_text())
            self.entries = {
                name: Entry(**data) for name, data in raw.get("targets", {}).items()
            }

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "targets": {n: asdict(e) for n, e in self.entries.items()}}
        self.path.write_text(json.dumps(data, indent=2))

    def get(self, target: str) -> Entry | None:
        return self.entries.get(target)

    def put(self, target: str, entry: Entry) -> None:
        self.entries[target] = entry

    def is_fresh(self, target: str, key: str, root: Path) -> bool:
        """True if ``target`` was built with ``key`` and its artifact exists."""
        entry = self.entries.get(target)
        if entry is None or entry.key != key:
            return False
        return (root / entry.artifact).is_file()

    def clear(self) -> None:
        self.entries = {}
        if self.path.is_file():
            self.path.unlink()
