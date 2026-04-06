"""OpenAI Codex CLI session provider.

Handles discovery, export, and import of Codex CLI sessions stored in ~/.codex/.

Codex CLI data layout (from source: codex-rs/rollout/):
  ~/.codex/
    config.toml                          - global config (MCP servers, model)
    history.jsonl                                   - cross-session command history (text-only)
    session_index.jsonl                             - thread name <-> ID index (append-only JSONL)
    sessions/                                       - active session rollout files
      [YYYY/MM/DD/]rollout-{YYYY-MM-DDTHH-MM-SS}-{uuid}.jsonl
      (may be flat or in date-partitioned subdirectories)
    archived_sessions/                              - older archived sessions (flat)
      rollout-{YYYY-MM-DDTHH-MM-SS}-{uuid}.jsonl
    memories/                                       - extracted memories
      raw_memories.md
    log/                                            - logs
      codex-tui.log

Each rollout .jsonl file:
  Line 1: SessionMetaLine {meta: {id, timestamp, source, cwd},
           git: {commit_hash, branch, origin_url}}
  Subsequent lines: RolloutItem entries (conversation turns, tool calls, results)

Filename format: rollout-YYYY-MM-DDTHH-MM-SS-{uuid}.jsonl
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.bundle import BundleBuilder, BundleReader
from ..utils.display import info
from ..utils.paths import get_codex_dir
from .base import SessionInfo, SessionProvider

ROLLOUT_PREFIX = "rollout-"
ROLLOUT_SUFFIX = ".jsonl"
SESSIONS_SUBDIR = "sessions"
ARCHIVED_SESSIONS_SUBDIR = "archived_sessions"

# Pattern: rollout-YYYY-MM-DDTHH-MM-SS-{uuid}.jsonl
ROLLOUT_FILENAME_RE = re.compile(
    r"^rollout-(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})-([0-9a-f\-]{36})\.jsonl$"
)


def _parse_rollout_filename(name: str) -> tuple[str, str] | None:
    """Parse a rollout filename into (timestamp, uuid). Returns None if not a rollout file."""
    m = ROLLOUT_FILENAME_RE.match(name)
    if m:
        ts = m.group(1).replace("T", " ").replace("-", ":", 2)  # Rough readable timestamp
        return ts, m.group(2)
    return None


def _read_session_meta(path: Path) -> dict | None:
    """Read the first line of a rollout JSONL to extract SessionMetaLine."""
    try:
        with open(path) as f:
            first_line = f.readline().strip()
            if first_line:
                return json.loads(first_line)
    except (json.JSONDecodeError, OSError):
        pass
    return None


class CodexCliProvider(SessionProvider):
    name = "codex_cli"

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or get_codex_dir()

    def _find_all_rollouts(self) -> list[Path]:
        """Find all rollout files in sessions/ and archived_sessions/."""
        rollouts = []
        for name in [SESSIONS_SUBDIR, ARCHIVED_SESSIONS_SUBDIR]:
            subdir = self.base_dir / name
            if subdir.exists():
                rollouts.extend(
                    f for f in subdir.rglob(f"{ROLLOUT_PREFIX}*{ROLLOUT_SUFFIX}")
                    if f.is_file()
                )
        return rollouts

    def list_sessions(self) -> list[SessionInfo]:
        sessions = []
        if not self.base_dir.exists():
            return sessions

        for rollout_path in self._find_all_rollouts():
            parsed = _parse_rollout_filename(rollout_path.name)
            if not parsed:
                continue

            timestamp_str, uuid_str = parsed

            # Try to extract richer metadata from the first line
            meta = _read_session_meta(rollout_path)
            cwd = ""
            started_at = timestamp_str
            session_id = uuid_str

            if meta and "meta" in meta:
                m = meta["meta"]
                session_id = m.get("id", uuid_str)
                cwd = m.get("cwd", "")
                started_at = m.get("timestamp", timestamp_str)

            is_archived = ARCHIVED_SESSIONS_SUBDIR in str(rollout_path)

            sessions.append(SessionInfo(
                provider=self.name,
                session_id=session_id,
                cwd=cwd,
                started_at=started_at,
                extra={
                    "rollout_file": rollout_path.name,
                    "archived": is_archived,
                    "size": rollout_path.stat().st_size,
                },
            ))

        sessions.sort(key=lambda s: s.started_at, reverse=True)
        return sessions

    def _find_rollout_by_id(self, session_id: str) -> Path | None:
        """Find a rollout file matching a session ID (prefix match on UUID)."""
        for rollout_path in self._find_all_rollouts():
            # Check filename UUID
            parsed = _parse_rollout_filename(rollout_path.name)
            if parsed and parsed[1].startswith(session_id):
                return rollout_path

            # Check embedded session meta ID
            meta = _read_session_meta(rollout_path)
            if meta and "meta" in meta:
                meta_id = str(meta["meta"].get("id", ""))
                if meta_id.startswith(session_id):
                    return rollout_path

        return None

    def export_session(self, session_id: str, builder: BundleBuilder) -> None:
        if not self.base_dir.exists():
            raise ValueError(f"Codex CLI directory not found: {self.base_dir}")

        rollout_path = self._find_rollout_by_id(session_id)
        if not rollout_path:
            raise ValueError(f"No rollout file found for session: {session_id}")

        info(f"Exporting Codex CLI session {session_id[:12]}...")

        # 1. The rollout file itself (the core session data)
        rel_rollout = rollout_path.relative_to(self.base_dir)
        builder.add_file(f"session/{rel_rollout}", rollout_path.read_bytes())
        info(f"  Rollout file: {rollout_path.name} ({rollout_path.stat().st_size:,} bytes)")

        # 2. Global config
        config_toml = self.base_dir / "config.toml"
        if config_toml.exists():
            builder.add_file("session/config.toml", config_toml.read_bytes())

        # 3. Session index (for thread name resolution)
        session_index = self.base_dir / "session_index.jsonl"
        if session_index.exists():
            builder.add_file("session/session_index.jsonl", session_index.read_bytes())

        # 4. Cross-session history
        history = self.base_dir / "history.jsonl"
        if history.exists():
            builder.add_file("session/history.jsonl", history.read_bytes())

        # 5. Memories (can be useful for context continuity)
        memories_dir = self.base_dir / "memories"
        if memories_dir.exists():
            count = builder.add_directory_tree("session/memories", memories_dir)
            if count:
                info(f"  Memories: {count} files")

        info("  Export complete")

    def import_session(self, reader: BundleReader, target_dir: str | None = None) -> None:
        manifest = reader.manifest
        info(f"Importing Codex CLI session {manifest.session_id[:12]}...")

        files = reader.list_files()
        imported = 0

        for file_path in files:
            if not file_path.startswith("session/"):
                continue

            rel = file_path[len("session/"):]
            content = reader.read_file(file_path)

            target = self.base_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)

            # For rollout files, optionally rewrite the cwd in session meta
            is_rollout = rel.startswith(SESSIONS_SUBDIR + "/") and rel.endswith(ROLLOUT_SUFFIX)
            if is_rollout and target_dir:
                content = self._rewrite_rollout_cwd(content, manifest.source_cwd, target_dir)

            target.write_bytes(content)
            imported += 1

        info(f"  Imported {imported} files to {self.base_dir}")

    @staticmethod
    def _rewrite_rollout_cwd(content: bytes, source_cwd: str, target_cwd: str) -> bytes:
        """Rewrite the cwd in the first line (SessionMetaLine) of a rollout file."""
        try:
            text = content.decode()
            lines = text.split("\n", 1)
            if lines:
                meta = json.loads(lines[0])
                if "meta" in meta and meta["meta"].get("cwd") == source_cwd:
                    meta["meta"]["cwd"] = target_cwd
                    lines[0] = json.dumps(meta, separators=(",", ":"))
                    return "\n".join(lines).encode()
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
            pass
        return content
