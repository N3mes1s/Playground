"""Convert Codex CLI sessions to Claude Code format."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..core.bundle import BundleReader
from ..utils.display import info, warning
from ..utils.paths import encode_cwd
from .base import SessionConverter, parse_codex_jsonl

if TYPE_CHECKING:
    from ..core.manifest import Manifest

# Deterministic namespace for generating UUIDs during conversion
_CONVERSION_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


class CodexToClaudeConverter(SessionConverter):
    source_provider = "codex_cli"
    target_provider = "claude_code"

    def convert(self, reader: BundleReader, target_cwd: str | None = None) -> BundleReader:
        manifest = reader.manifest
        session_id = manifest.session_id

        info("Converting Codex CLI session to Claude Code format...")

        # 1. Find and parse the rollout file
        rollout_data = self._find_rollout(reader)
        if not rollout_data:
            raise ValueError(f"No rollout file found for session {session_id}")

        meta, messages = parse_codex_jsonl(rollout_data)

        # 2. Determine CWD and session metadata
        codex_cwd = ""
        if meta and "meta" in meta:
            codex_cwd = meta["meta"].get("cwd", "")
        cwd = target_cwd or codex_cwd or manifest.source_cwd

        # Get or generate session ID
        codex_session_id = session_id
        if meta and "meta" in meta:
            codex_session_id = meta["meta"].get("id", session_id)

        # Parse timestamp
        started_at_ms = self._parse_timestamp_ms(meta, manifest)

        encoded_cwd = encode_cwd(cwd)

        info(f"  Session: {codex_session_id[:12]}... CWD: {cwd}")

        # 3. Convert messages to Claude Code JSONL
        claude_lines = self._convert_messages(
            messages, codex_session_id, cwd, meta
        )

        # 4. Build session metadata file
        session_meta = {
            "pid": 0,
            "sessionId": codex_session_id,
            "cwd": cwd,
            "startedAt": started_at_ms,
            "kind": "imported",
        }

        # 5. Build new bundle files
        files: dict[str, bytes] = {}
        files["session/sessions/0.json"] = json.dumps(session_meta, indent=2).encode()

        jsonl_content = "\n".join(json.dumps(line) for line in claude_lines) + "\n"
        files[f"session/projects/{encoded_cwd}/{codex_session_id}.jsonl"] = (
            jsonl_content.encode()
        )

        # Copy git and env files from original bundle
        for f in reader.list_files():
            if f.startswith("git/") or f.startswith("env/"):
                files[f] = reader.read_file(f)

        # Emit conversion warnings
        warning("Codex messages imported as plain text (no tool use blocks)")
        warning("Synthetic UUIDs generated for message threading")
        warning("Session marked as kind=imported with pid=0")

        new_manifest = self._build_manifest(manifest, cwd, codex_session_id)
        return self._rebuild_bundle(new_manifest, files)

    def _find_rollout(self, reader: BundleReader) -> bytes | None:
        """Find the rollout .jsonl file in the bundle."""
        for f in reader.list_files():
            if f.startswith("session/") and f.endswith(".jsonl"):
                return reader.read_file(f)
        return None

    def _parse_timestamp_ms(self, meta: dict | None, manifest: Manifest) -> int:
        """Extract or generate a startedAt timestamp in epoch milliseconds."""
        if meta and "meta" in meta:
            ts_str = meta["meta"].get("timestamp", "")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    return int(dt.timestamp() * 1000)
                except (ValueError, AttributeError):
                    pass

        # Fallback to manifest created_at
        try:
            dt = datetime.fromisoformat(manifest.created_at)
            return int(dt.timestamp() * 1000)
        except (ValueError, AttributeError):
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    def _convert_messages(
        self,
        messages: list[dict],
        session_id: str,
        cwd: str,
        meta: dict | None,
    ) -> list[dict]:
        """Convert Codex messages to Claude Code JSONL lines."""
        lines = []
        parent_uuid: str | None = None

        # Use session start time as base, increment by 1s per message
        base_ts = ""
        if meta and "meta" in meta:
            base_ts = meta["meta"].get("timestamp", "")

        for i, msg in enumerate(messages):
            msg_type = msg.get("type", "")
            content = msg.get("content", "")
            timestamp = msg.get("timestamp", "") or base_ts

            if not content:
                continue

            # Map Codex types to Claude Code roles
            if msg_type == "user_message":
                role = "user"
                line_type = "user"
            elif msg_type == "assistant_message":
                role = "assistant"
                line_type = "assistant"
            else:
                # Unknown type — treat as assistant
                role = "assistant"
                line_type = "assistant"

            # Generate deterministic UUID
            msg_uuid = str(uuid.uuid5(_CONVERSION_NAMESPACE, f"{session_id}-{i}"))

            line = {
                "type": line_type,
                "message": {
                    "role": role,
                    "content": content,
                },
                "uuid": msg_uuid,
                "parentUuid": parent_uuid,
                "timestamp": timestamp,
                "sessionId": session_id,
                "cwd": cwd,
                "version": "1.0-imported",
                "isSidechain": False,
            }

            lines.append(line)
            parent_uuid = msg_uuid

        return lines

    def _build_manifest(
        self, original: Manifest, cwd: str, session_id: str
    ) -> Manifest:
        """Build a new manifest for the converted bundle."""
        from ..core.manifest import Manifest

        return Manifest(
            provider="claude_code",
            session_id=session_id,
            source_hostname=original.source_hostname,
            source_platform=original.source_platform,
            source_cwd=cwd,
            components=original.components,
            converted_from="codex_cli",
        )
