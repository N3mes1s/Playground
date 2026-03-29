"""Test fixtures for session-teleport."""

import json

import pytest


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
        json.dumps({"type": "user", "content": "Hello",
                     "timestamp": "2025-01-15T10:30:01Z"}),
        json.dumps({"type": "assistant", "content": "Hi there!",
                     "timestamp": "2025-01-15T10:30:02Z"}),
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
    """Create a fake ~/.codex directory with test session data matching real Codex CLI format."""
    codex_dir = tmp_path / ".codex"
    sessions_dir = codex_dir / "sessions"
    sessions_dir.mkdir(parents=True)

    session_uuid = "5973b6c0-94b8-487b-a530-2aeb6098ae0e"
    cwd = str(tmp_path / "codex-project")
    rollout_name = f"rollout-2025-05-07T17-24-21-{session_uuid}.jsonl"

    # First line: SessionMetaLine
    session_meta = {
        "meta": {
            "id": session_uuid,
            "timestamp": "2025-05-07T17:24:21Z",
            "source": "cli",
            "cwd": cwd,
            "cli_version": "0.1.0",
            "model_provider": "openai",
        },
        "git": {
            "commit_hash": "abc123",
            "branch": "main",
            "origin_url": "https://github.com/example/repo.git",
        },
    }
    # Subsequent lines: RolloutItem entries
    rollout_items = [
        {"type": "user_message", "content": "Hello codex"},
        {"type": "assistant_message", "content": "Hi! How can I help?"},
    ]
    lines = [json.dumps(session_meta)]
    lines.extend(json.dumps(item) for item in rollout_items)
    (sessions_dir / rollout_name).write_text("\n".join(lines) + "\n")

    # Config
    (codex_dir / "config.toml").write_text('[model]\nprovider = "openai"\n')

    # Session index
    index_entry = {
        "id": session_uuid,
        "thread_name": "test thread",
        "updated_at": "2025-05-07T17:24:21Z",
    }
    (codex_dir / "session_index.jsonl").write_text(json.dumps(index_entry) + "\n")

    # Create project dir
    project = tmp_path / "codex-project"
    project.mkdir(parents=True)

    return codex_dir, session_uuid, cwd
