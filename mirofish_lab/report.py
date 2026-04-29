"""Markdown report builder. Tiny, no jinja."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Report:
    title: str
    sections: list[tuple[str, str]] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)

    def add(self, heading: str, body: str) -> None:
        self.sections.append((heading, body))

    def render(self) -> str:
        lines: list[str] = [f"# {self.title}", ""]
        if self.meta:
            lines.append("> " + " · ".join(f"{k}: {v}" for k, v in self.meta.items()))
            lines.append("")
        lines.append(f"_Generated {datetime.utcnow().isoformat(timespec='seconds')}Z_")
        lines.append("")
        for heading, body in self.sections:
            lines.append(f"## {heading}")
            lines.append("")
            lines.append(body.strip())
            lines.append("")
        return "\n".join(lines)

    def write(self, path: Path | str) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.render())
        return p
