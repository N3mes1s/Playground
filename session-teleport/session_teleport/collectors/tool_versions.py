"""Capture installed tool versions for session compatibility checking."""

from __future__ import annotations

import json
import subprocess


def _get_version(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout.strip().split("\n")[0]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def capture_tool_versions() -> dict[str, bytes]:
    """Capture versions of relevant tools. Returns {filename: content}."""
    versions = {
        "python": _get_version(["python3", "--version"]),
        "node": _get_version(["node", "--version"]),
        "git": _get_version(["git", "--version"]),
        "claude": _get_version(["claude", "--version"]),
    }

    # Filter out empty entries
    versions = {k: v for k, v in versions.items() if v}

    return {"env/tool_versions.json": json.dumps(versions, indent=2).encode()}
