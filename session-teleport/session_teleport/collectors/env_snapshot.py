"""Capture filtered environment variables."""

from __future__ import annotations

import json
import os

from ..security.secret_filter import filter_env
from ..utils.display import info, warning


def capture_env() -> dict[str, bytes]:
    """Capture filtered environment variables. Returns {filename: content} for the bundle."""
    env = dict(os.environ)
    safe_env, redacted = filter_env(env)

    if redacted:
        warning(f"Redacted {len(redacted)} env vars: {', '.join(redacted[:5])}")
        if len(redacted) > 5:
            warning(f"  ...and {len(redacted) - 5} more")

    info(f"  Environment: {len(safe_env)} variables captured, {len(redacted)} redacted")

    files: dict[str, bytes] = {}
    files["env/filtered_env.json"] = json.dumps(safe_env, indent=2).encode()
    files["env/redacted_names.json"] = json.dumps(redacted).encode()
    return files


def restore_env_info(reader) -> dict:
    """Read environment snapshot from a bundle. Returns the env dict for display."""
    try:
        data = reader.read_file("env/filtered_env.json")
        return json.loads(data.decode())
    except FileNotFoundError:
        return {}
