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

    Claude Code's encoding replaces "/" with "-", which is lossy when directory
    names contain hyphens. We attempt to resolve the real path by checking the
    filesystem; if that fails, we fall back to naive replacement.
    """
    if not encoded:
        return encoded

    # Try filesystem resolution: check progressively longer path prefixes
    # to disambiguate hyphens-as-separators from hyphens-in-names.
    if encoded.startswith("-"):
        resolved = _resolve_encoded_path(encoded[1:].split("-"))
        if resolved:
            return resolved

    # Naive fallback (lossy for paths with hyphens in directory names)
    if encoded.startswith("-"):
        return "/" + encoded[1:].replace("-", "/")
    return encoded.replace("-", "/")


def _resolve_encoded_path(parts: list[str]) -> str | None:
    """Try to reconstruct the original path by testing the filesystem.

    Given parts ["home", "user", "my", "project"], tries to find whether
    each position is a separator or a hyphen by checking which directories
    actually exist on disk.
    """
    if not parts:
        return None

    def _search(current: Path, remaining: list[str]) -> str | None:
        if not remaining:
            return str(current)

        # Greedily try longer hyphenated names first
        for i in range(len(remaining), 0, -1):
            candidate_name = "-".join(remaining[:i])
            candidate_path = current / candidate_name
            if candidate_path.exists():
                result = _search(candidate_path, remaining[i:])
                if result is not None:
                    return result
        return None

    return _search(Path("/"), parts)


def get_hostname() -> str:
    return socket.gethostname()


def get_platform() -> str:
    return platform.system().lower()
