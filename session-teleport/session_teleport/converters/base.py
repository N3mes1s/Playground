"""Shared utilities for cross-provider session conversion."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from ..core.bundle import BundleBuilder, BundleReader
from ..core.manifest import Manifest


class SessionConverter(ABC):
    """Converts session data from one provider format to another."""

    source_provider: str
    target_provider: str

    @abstractmethod
    def convert(self, reader: BundleReader, target_cwd: str | None = None) -> BundleReader:
        """Read session files from reader, convert, return a new BundleReader."""
        ...

    def _rebuild_bundle(self, manifest: Manifest, files: dict[str, bytes]) -> BundleReader:
        """Build a new unencrypted BundleReader from converted files."""
        builder = BundleBuilder(manifest)
        for path, content in files.items():
            builder.add_file(path, content)
        data = builder.build()
        return BundleReader(data)


def flatten_content(content: str | list) -> str:
    """Flatten Claude Code message.content to plain text.

    Handles:
    - Plain string content
    - Array of {type: "text", text: "..."} blocks
    - Array with tool_use blocks: rendered as [Tool: name] summary
    - Array with tool_result blocks: rendered as [Result] content
    - Thinking blocks: stripped
    """
    if isinstance(content, str):
        return content

    if not isinstance(content, list):
        return str(content)

    parts = []
    for block in content:
        if not isinstance(block, dict):
            parts.append(str(block))
            continue

        block_type = block.get("type", "")

        if block_type == "text":
            text = block.get("text", "")
            if text:
                parts.append(text)

        elif block_type == "tool_use":
            name = block.get("name", "unknown")
            inp = block.get("input", {})
            summary = _summarize_tool_input(name, inp)
            parts.append(f"[Tool: {name}] {summary}")

        elif block_type == "tool_result":
            result_content = block.get("content", "")
            if isinstance(result_content, list):
                # Nested content array in tool results
                text_parts = []
                for item in result_content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, str):
                        text_parts.append(item)
                result_content = "\n".join(text_parts)
            if result_content:
                parts.append(f"[Result] {result_content}")

        elif block_type == "thinking":
            # Strip thinking blocks from conversion
            pass

        else:
            # Unknown block type — include as-is
            text = block.get("text", block.get("content", ""))
            if text:
                parts.append(str(text))

    return "\n".join(parts)


def _summarize_tool_input(name: str, inp: dict) -> str:
    """Create a short summary of tool input for display."""
    if not inp:
        return ""

    # Common patterns
    if "file_path" in inp:
        return inp["file_path"]
    if "command" in inp:
        cmd = inp["command"]
        return cmd[:100] + ("..." if len(cmd) > 100 else "")
    if "pattern" in inp:
        return f"pattern={inp['pattern']}"
    if "prompt" in inp:
        prompt = inp["prompt"]
        return prompt[:80] + ("..." if len(prompt) > 80 else "")

    # Fallback: first string value
    for v in inp.values():
        if isinstance(v, str) and v:
            return v[:80] + ("..." if len(v) > 80 else "")
    return json.dumps(inp)[:80]


def parse_claude_jsonl(data: bytes) -> list[dict]:
    """Parse a Claude Code JSONL conversation log.

    Skips compactMetadata lines and filters out sidechain messages.
    Returns messages in file order (which is chronological).
    """
    messages = []
    for line in data.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Skip metadata-only lines
        if msg.get("compactMetadata") or msg.get("isMeta"):
            continue

        # Skip sidechain messages (subagent conversations are separate files)
        if msg.get("isSidechain"):
            continue

        # Skip compact summaries (they're internal bookkeeping)
        if msg.get("isCompactSummary"):
            continue

        # Must have a message field with role
        if "message" in msg and "role" in msg.get("message", {}):
            messages.append(msg)

    return messages


def parse_codex_jsonl(data: bytes) -> tuple[dict | None, list[dict]]:
    """Parse a Codex CLI rollout JSONL file.

    Returns (meta_line, message_lines).
    First line with 'meta' key is the session metadata.
    Subsequent lines are message entries.
    """
    meta = None
    messages = []

    for line in data.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if meta is None and "meta" in entry:
            meta = entry
        else:
            messages.append(entry)

    return meta, messages
