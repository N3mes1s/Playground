"""Test fixtures for session-teleport."""

import json
import pytest
from pathlib import Path


@pytest.fixture
def tmp_claude_dir(tmp_path):
    """Create a fake ~/.claude directory with test session data."""
    claude_dir = tmp_path / ".claude"

    # Create session metadata
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)

    session_id = "test-session-1234-5678-abcdef"
    cwd = str(tmp_path / "myproject")

    session_meta = {
        "pid": 12345,
        "sessionId": session_id,
        "cwd": cwd,
        "startedAt": "2025-01-15T10:30:00Z",
        "kind": "interactive",
    }
    (sessions_dir / "12345.json").write_text(json.dumps(session_meta))

    # Create project directory with conversation log
    encoded_cwd = cwd.replace("/", "-")
    project_dir = claude_dir / "projects" / encoded_cwd
    project_dir.mkdir(parents=True)

    conv_lines = [
        json.dumps({"type": "user", "content": "Hello", "timestamp": "2025-01-15T10:30:01Z"}),
        json.dumps({"type": "assistant", "content": "Hi there!", "timestamp": "2025-01-15T10:30:02Z"}),
    ]
    (project_dir / f"{session_id}.jsonl").write_text("\n".join(conv_lines) + "\n")

    # Create subagent data
    subagent_dir = project_dir / session_id / "subagents"
    subagent_dir.mkdir(parents=True)
    (subagent_dir / "agent1.meta.json").write_text(json.dumps({
        "agentType": "Explore",
        "description": "test agent",
    }))

    # Create settings
    (claude_dir / "settings.json").write_text(json.dumps({"theme": "dark"}))

    # Create the project working directory with a git repo
    project = tmp_path / "myproject"
    project.mkdir(parents=True)
    (project / "main.py").write_text("print('hello')\n")

    return claude_dir, session_id, cwd


@pytest.fixture
def tmp_codex_dir(tmp_path):
    """Create a fake ~/.codex directory with test session data."""
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir(parents=True)

    session_id = "codex-session-abcd-1234"
    (codex_dir / f"{session_id}.json").write_text(json.dumps({
        "session_id": session_id,
        "cwd": str(tmp_path / "codex-project"),
        "created_at": "2025-01-20T14:00:00Z",
    }))

    return codex_dir, session_id
