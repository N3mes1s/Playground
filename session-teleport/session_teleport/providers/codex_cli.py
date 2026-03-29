"""OpenAI Codex CLI session provider.

Handles discovery, export, and import of Codex CLI sessions stored in ~/.codex/.

Note: The Codex CLI session format is less well-documented than Claude Code.
This provider attempts to discover and package sessions based on observed patterns.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import SessionProvider, SessionInfo
from ..core.bundle import BundleBuilder, BundleReader
from ..utils.paths import get_codex_dir
from ..utils.display import info, warning


class CodexCliProvider(SessionProvider):
    name = "codex_cli"

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or get_codex_dir()

    def list_sessions(self) -> list[SessionInfo]:
        sessions = []
        if not self.base_dir.exists():
            return sessions

        # Codex stores sessions in various formats; scan for session-like JSON files
        for candidate in self.base_dir.rglob("*.json"):
            try:
                data = json.loads(candidate.read_text())
                # Look for session-like structures
                if "session_id" in data or "id" in data:
                    sessions.append(SessionInfo(
                        provider=self.name,
                        session_id=data.get("session_id", data.get("id", candidate.stem)),
                        cwd=data.get("cwd", data.get("working_directory", "")),
                        started_at=data.get("created_at", data.get("started_at", "")),
                    ))
            except (json.JSONDecodeError, KeyError):
                continue

        # Also check for conversation history files
        for jsonl_file in self.base_dir.rglob("*.jsonl"):
            session_id = jsonl_file.stem
            if not any(s.session_id == session_id for s in sessions):
                stat = jsonl_file.stat()
                sessions.append(SessionInfo(
                    provider=self.name,
                    session_id=session_id,
                    cwd="",
                    started_at="",
                    extra={"file": str(jsonl_file), "size": stat.st_size},
                ))

        sessions.sort(key=lambda s: s.started_at, reverse=True)
        return sessions

    def export_session(self, session_id: str, builder: BundleBuilder) -> None:
        if not self.base_dir.exists():
            raise ValueError(f"Codex CLI directory not found: {self.base_dir}")

        info(f"Exporting Codex CLI session {session_id[:12]}...")

        # Package the entire codex directory structure for this session
        exported = 0
        for file in self.base_dir.rglob("*"):
            if not file.is_file():
                continue
            # Include files that match the session ID or appear to be global config
            rel = file.relative_to(self.base_dir)
            if session_id in str(rel) or file.name in ("config.json", "settings.json"):
                builder.add_file(f"session/{rel}", file.read_bytes())
                exported += 1

        if exported == 0:
            warning(f"No files found for session {session_id}")
        else:
            info(f"  Exported {exported} files")

    def import_session(self, reader: BundleReader, target_dir: str | None = None) -> None:
        manifest = reader.manifest
        info(f"Importing Codex CLI session {manifest.session_id[:12]}...")

        count = reader.extract_prefix("session", self.base_dir)
        info(f"  Imported {count} files to {self.base_dir}")
