"""Convert Claude Code sessions to Codex CLI format."""

from __future__ import annotations

import json
import uuid

from ..core.bundle import BundleReader
from ..core.manifest import Manifest
from ..utils.display import info, warning
from .base import SessionConverter, flatten_content, parse_claude_jsonl


class ClaudeToCodexConverter(SessionConverter):
    source_provider = "claude_code"
    target_provider = "codex_cli"

    def convert(self, reader: BundleReader, target_cwd: str | None = None) -> BundleReader:
        manifest = reader.manifest
        session_id = manifest.session_id
        cwd = target_cwd or manifest.source_cwd

        info("Converting Claude Code session to Codex CLI format...")

        # 1. Find the main conversation log
        main_jsonl = self._find_main_jsonl(reader, session_id)
        if not main_jsonl:
            raise ValueError(f"No conversation log found for session {session_id}")

        # 2. Parse main conversation
        main_messages = parse_claude_jsonl(main_jsonl)

        # 3. Find and parse subagent conversations
        subagent_data = self._collect_subagents(reader, session_id)

        # 4. Build Codex meta line
        meta_line = self._build_meta_line(manifest, reader, cwd)

        # 5. Convert messages
        rollout_lines = [meta_line]
        rollout_lines.extend(
            self._convert_messages(main_messages, subagent_data)
        )

        # 6. Generate rollout filename
        timestamp = manifest.created_at.replace(":", "-").replace("+", "-")[:19]
        rollout_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, session_id))
        rollout_name = f"rollout-{timestamp}-{rollout_uuid}.jsonl"

        # 7. Build new bundle
        files: dict[str, bytes] = {}
        rollout_data = "\n".join(json.dumps(line) for line in rollout_lines) + "\n"
        files[f"session/sessions/{rollout_name}"] = rollout_data.encode()

        # Copy git and env files from original bundle
        for f in reader.list_files():
            if f.startswith("git/") or f.startswith("env/"):
                files[f] = reader.read_file(f)

        # Emit conversion warnings
        warning("Tool use/result blocks flattened to text")
        if subagent_data:
            warning(f"Inlined {len(subagent_data)} subagent conversations")
        warning("Session tree structure flattened to linear sequence")

        new_manifest = self._build_manifest(manifest, cwd)
        return self._rebuild_bundle(new_manifest, files)

    def _find_main_jsonl(self, reader: BundleReader, session_id: str) -> bytes | None:
        """Find the main conversation .jsonl file in the bundle."""
        for f in reader.list_files():
            if f.endswith(f"{session_id}.jsonl") and "/subagents/" not in f:
                return reader.read_file(f)
        return None

    def _collect_subagents(
        self, reader: BundleReader, session_id: str
    ) -> dict[str, dict]:
        """Collect subagent conversations and metadata.

        Returns {agent_id: {"meta": {...}, "messages": [...]}}
        """
        subagents: dict[str, dict] = {}
        files = reader.list_files()

        # Find .meta.json files first
        for f in files:
            if "/subagents/" in f and f.endswith(".meta.json"):
                try:
                    meta = json.loads(reader.read_file(f).decode())
                    agent_id = f.split("/")[-1].replace(".meta.json", "")
                    subagents[agent_id] = {"meta": meta, "messages": []}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

        # Find matching .jsonl files
        for f in files:
            if "/subagents/" in f and f.endswith(".jsonl"):
                agent_id = f.split("/")[-1].replace(".jsonl", "")
                if agent_id in subagents:
                    try:
                        msgs = parse_claude_jsonl(reader.read_file(f))
                        subagents[agent_id]["messages"] = msgs
                    except (UnicodeDecodeError, ValueError):
                        continue

        return subagents

    def _convert_messages(
        self, messages: list[dict], subagent_data: dict[str, dict]
    ) -> list[dict]:
        """Convert Claude messages to Codex rollout entries."""
        entries = []

        for msg in messages:
            message = msg.get("message", {})
            role = message.get("role", "")
            content = message.get("content", "")
            timestamp = msg.get("timestamp", "")

            # Check if this message triggers a subagent
            if isinstance(content, list):
                for block in content:
                    is_agent_tool = (
                        isinstance(block, dict)
                        and block.get("type") == "tool_use"
                        and block.get("name") == "Agent"
                    )
                    if is_agent_tool:
                        agent_id = self._find_agent_id_for_tool(msg, block)
                        if agent_id and agent_id in subagent_data:
                            entries.extend(
                                self._inline_subagent(subagent_data[agent_id])
                            )

            flat = flatten_content(content)
            if not flat.strip():
                continue

            if role == "user":
                entries.append({
                    "type": "user_message",
                    "content": flat,
                    "timestamp": timestamp,
                })
            elif role == "assistant":
                entries.append({
                    "type": "assistant_message",
                    "content": flat,
                    "timestamp": timestamp,
                })

        return entries

    def _find_agent_id_for_tool(self, msg: dict, tool_block: dict) -> str | None:
        """Try to find the agent ID from tool result metadata."""
        tool_use_result = msg.get("toolUseResult", {})
        if tool_use_result:
            return tool_use_result.get("agentId")
        return None

    def _inline_subagent(self, subagent: dict) -> list[dict]:
        """Convert a subagent conversation to inline Codex messages."""
        entries = []
        meta = subagent.get("meta", {})
        agent_type = meta.get("agentType", "unknown")
        description = meta.get("description", "")

        # Add a marker message
        entries.append({
            "type": "assistant_message",
            "content": f"[Subagent: {agent_type}] {description}",
            "timestamp": "",
        })

        for msg in subagent.get("messages", []):
            message = msg.get("message", {})
            role = message.get("role", "")
            content = message.get("content", "")
            flat = flatten_content(content)
            if not flat.strip():
                continue

            msg_type = "user_message" if role == "user" else "assistant_message"
            entries.append({
                "type": msg_type,
                "content": f"[{agent_type}] {flat}",
                "timestamp": msg.get("timestamp", ""),
            })

        return entries

    def _build_meta_line(
        self, manifest: Manifest, reader: BundleReader, cwd: str
    ) -> dict:
        """Build the Codex SessionMetaLine from manifest and git data."""
        meta_line: dict = {
            "meta": {
                "id": manifest.session_id,
                "timestamp": manifest.created_at,
                "source": "converted-from-claude",
                "cwd": cwd,
            },
            "git": {},
        }

        # Pull git info from bundle if available
        try:
            branch = reader.read_file("git/branch.txt").decode().strip()
            meta_line["git"]["branch"] = branch
        except FileNotFoundError:
            pass

        try:
            commit = reader.read_file("git/commit.txt").decode().strip()
            meta_line["git"]["commit_hash"] = commit
        except FileNotFoundError:
            pass

        try:
            remote = reader.read_file("git/remote.txt").decode().strip()
            meta_line["git"]["origin_url"] = remote
        except FileNotFoundError:
            pass

        return meta_line

    def _build_manifest(self, original: Manifest, cwd: str) -> Manifest:
        """Build a new manifest for the converted bundle."""
        return Manifest(
            provider="codex_cli",
            session_id=original.session_id,
            source_hostname=original.source_hostname,
            source_platform=original.source_platform,
            source_cwd=cwd,
            components=original.components,
            converted_from="claude_code",
        )
