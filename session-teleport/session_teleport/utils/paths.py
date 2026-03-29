"""Platform-aware path resolution for session data directories."""

import platform
import socket
from pathlib import Path


def get_claude_dir() -> Path:
    """Return the Claude Code data directory (~/.claude)."""
    return Path.home() / ".claude"


def get_codex_dir() -> Path:
    """Return the Codex CLI data directory (~/.codex)."""
    return Path.home() / ".codex"


def encode_cwd(cwd: str) -> str:
    """Encode a working directory path the way Claude Code does.

    Claude Code replaces path separators with hyphens and strips the leading slash.
    e.g. /home/user/project -> -home-user-project
    """
    return cwd.replace("/", "-").replace("\\", "-")


def decode_cwd(encoded: str) -> str:
    """Best-effort decode of an encoded CWD back to a path.

    This is lossy since directory names could contain hyphens.
    The encoded form starts with a leading hyphen (from the leading /).
    """
    if encoded.startswith("-"):
        return "/" + encoded[1:].replace("-", "/")
    return encoded.replace("-", "/")


def get_hostname() -> str:
    return socket.gethostname()


def get_platform() -> str:
    return platform.system().lower()
