"""Claude Code session provider.

Handles discovery, export, and import of Claude Code sessions stored in ~/.claude/.

Session data layout:
  ~/.claude/
    sessions/{pid}.json                           - process metadata (sessionId, cwd, pid)
    projects/{encoded-cwd}/{sessionId}.jsonl       - conversation log
    projects/{encoded-cwd}/{sessionId}/            - subagents and tool results
    session-env/{sessionId}                        - environment state
    settings.json                                  - global settings
    shell-snapshots/                               - shell environment snapshots
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import SessionProvider, SessionInfo
from ..core.bundle import BundleBuilder, BundleReader
from ..utils.paths import get_claude_dir, encode_cwd
from ..utils.display import info, warning


class ClaudeCodeProvider(SessionProvider):
    name = "claude_code"

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or get_claude_dir()

    def list_sessions(self) -> list[SessionInfo]:
        sessions = []
        sessions_dir = self.base_dir / "sessions"
        if not sessions_dir.exists():
            return sessions

        for session_file in sessions_dir.glob("*.json"):
            try:
                data = json.loads(session_file.read_text())
                # startedAt is epoch milliseconds
                started_raw = data.get("startedAt", "")
                if isinstance(started_raw, (int, float)):
                    from datetime import datetime, timezone
                    started_at = datetime.fromtimestamp(
                        started_raw / 1000, tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                else:
                    started_at = str(started_raw)

                sessions.append(SessionInfo(
                    provider=self.name,
                    session_id=data.get("sessionId", ""),
                    cwd=data.get("cwd", ""),
                    started_at=started_at,
                    pid=data.get("pid"),
                ))
            except (json.JSONDecodeError, KeyError):
                continue

        sessions.sort(key=lambda s: s.started_at, reverse=True)
        return sessions

    def _find_session_file(self, session_id: str) -> tuple[Path | None, dict]:
        """Find the sessions/*.json file for a given session ID."""
        sessions_dir = self.base_dir / "sessions"
        if not sessions_dir.exists():
            return None, {}

        for session_file in sessions_dir.glob("*.json"):
            try:
                data = json.loads(session_file.read_text())
                if data.get("sessionId") == session_id:
                    return session_file, data
            except (json.JSONDecodeError, KeyError):
                continue
        return None, {}

    def export_session(self, session_id: str, builder: BundleBuilder) -> None:
        # Find session metadata
        session_file, meta = self._find_session_file(session_id)
        if not session_file:
            raise ValueError(f"Session {session_id} not found in {self.base_dir}/sessions/")

        cwd = meta.get("cwd", "")
        encoded = encode_cwd(cwd)
        info(f"Exporting Claude Code session {session_id[:12]}... (cwd: {cwd})")

        # 1. Session metadata file
        builder.add_file(
            f"session/sessions/{session_file.name}",
            session_file.read_bytes(),
        )

        # 2. Conversation log
        projects_dir = self.base_dir / "projects"
        conv_log = projects_dir / encoded / f"{session_id}.jsonl"
        if conv_log.exists():
            builder.add_file(
                f"session/projects/{encoded}/{session_id}.jsonl",
                conv_log.read_bytes(),
            )
            info(f"  Conversation log: {conv_log.stat().st_size:,} bytes")
        else:
            warning(f"  Conversation log not found at {conv_log}")

        # 3. Subagents and tool results directory
        session_data_dir = projects_dir / encoded / session_id
        if session_data_dir.exists():
            count = builder.add_directory_tree(
                f"session/projects/{encoded}/{session_id}",
                session_data_dir,
            )
            info(f"  Session data files: {count}")

        # 4. Session environment (can be a file or directory)
        env_path = self.base_dir / "session-env" / session_id
        if env_path.exists():
            if env_path.is_file():
                builder.add_file(
                    f"session/session-env/{session_id}",
                    env_path.read_bytes(),
                )
            elif env_path.is_dir():
                builder.add_directory_tree(
                    f"session/session-env/{session_id}",
                    env_path,
                )

        # 5. Settings (global, but useful for reproducing the environment)
        settings_file = self.base_dir / "settings.json"
        if settings_file.exists():
            builder.add_file(
                "session/settings.json",
                settings_file.read_bytes(),
            )

        # 6. CLAUDE.md project instructions (if present in cwd)
        claude_md = Path(cwd) / "CLAUDE.md"
        if claude_md.exists():
            builder.add_file("session/CLAUDE.md", claude_md.read_bytes())

    def import_session(self, reader: BundleReader, target_dir: str | None = None) -> None:
        manifest = reader.manifest
        source_cwd = manifest.source_cwd

        # Determine target encoded CWD
        if target_dir:
            target_encoded = encode_cwd(target_dir)
            source_encoded = encode_cwd(source_cwd)
        else:
            target_dir = source_cwd
            target_encoded = encode_cwd(source_cwd)
            source_encoded = target_encoded

        info(f"Importing Claude Code session {manifest.session_id[:12]}...")

        files = reader.list_files()
        imported = 0

        for file_path in files:
            if not file_path.startswith("session/"):
                continue

            rel = file_path[len("session/"):]
            content = reader.read_file(file_path)

            # Rewrite CWD in session metadata
            if rel.startswith("sessions/") and rel.endswith(".json"):
                data = json.loads(content)
                if target_dir != source_cwd:
                    data["cwd"] = target_dir
                target = self.base_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(data, indent=2))
                imported += 1
                continue

            # Rewrite encoded CWD in project paths
            if source_encoded != target_encoded:
                rel = rel.replace(
                    f"projects/{source_encoded}/",
                    f"projects/{target_encoded}/",
                )

            target = self.base_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            imported += 1

        info(f"  Imported {imported} files to {self.base_dir}")
