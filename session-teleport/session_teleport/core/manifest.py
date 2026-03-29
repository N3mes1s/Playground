"""Bundle manifest: metadata about the exported session bundle."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class Manifest:
    version: str = "1.0"
    created_at: str = ""
    provider: str = ""  # "claude_code" | "codex_cli"
    session_id: str = ""
    source_hostname: str = ""
    source_platform: str = ""
    source_cwd: str = ""
    bundle_checksum: str = ""
    encrypted: bool = False
    components: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> Manifest:
        return cls(**json.loads(data))

    @classmethod
    def from_dict(cls, d: dict) -> Manifest:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
