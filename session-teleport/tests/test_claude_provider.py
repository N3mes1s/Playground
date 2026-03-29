"""Tests for Claude Code provider."""

import json

from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest
from session_teleport.providers.claude_code import ClaudeCodeProvider


def test_list_sessions(tmp_claude_dir):
    claude_dir, session_id, cwd = tmp_claude_dir
    provider = ClaudeCodeProvider(base_dir=claude_dir)

    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].session_id == session_id
    assert sessions[0].cwd == cwd
    assert sessions[0].provider == "claude_code"


def test_export_session(tmp_claude_dir):
    claude_dir, session_id, cwd = tmp_claude_dir
    provider = ClaudeCodeProvider(base_dir=claude_dir)

    manifest = Manifest(provider="claude_code", session_id=session_id, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_id, builder)

    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()

    # Should have session metadata, conversation log, subagent, and settings
    assert any("sessions/" in f for f in files)
    assert any(".jsonl" in f for f in files)
    assert any("settings.json" in f for f in files)
    reader.close()


def test_export_import_roundtrip(tmp_claude_dir, tmp_path):
    claude_dir, session_id, cwd = tmp_claude_dir
    provider = ClaudeCodeProvider(base_dir=claude_dir)

    manifest = Manifest(provider="claude_code", session_id=session_id, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_id, builder)
    data = builder.build()

    # Import into a different claude dir
    target_claude = tmp_path / "target_claude"
    target_provider = ClaudeCodeProvider(base_dir=target_claude)

    reader = BundleReader(data)
    target_provider.import_session(reader)

    # Verify imported sessions
    imported = target_provider.list_sessions()
    assert len(imported) == 1
    assert imported[0].session_id == session_id
    reader.close()


def test_claude_started_at_epoch(tmp_path):
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    meta = {
        "pid": 1,
        "sessionId": "epoch-test",
        "cwd": "/tmp",
        "startedAt": 1700000000000,
    }
    (sessions_dir / "1.json").write_text(json.dumps(meta))
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert "2023" in sessions[0].started_at  # 1700000000000 ms = Nov 2023


def test_claude_export_session_env_dir(tmp_path):
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "env-dir-test"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(tmp_path), "startedAt": "2025-01-01"}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    # session-env as a directory with files inside
    env_dir = claude_dir / "session-env" / session_id
    env_dir.mkdir(parents=True)
    (env_dir / "vars.json").write_text('{"PATH": "/usr/bin"}')
    (env_dir / "shell.txt").write_text("bash")

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    builder = BundleBuilder(Manifest(session_id=session_id))
    provider.export_session(session_id, builder)
    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()
    assert any("session-env" in f for f in files)
    reader.close()


def test_claude_import_cwd_rewrite(tmp_path):
    """Import with target_dir rewrites CWD in metadata and project paths."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "rewrite-test"
    source_cwd = "/home/source/project"
    meta = {"pid": 1, "sessionId": session_id, "cwd": source_cwd, "startedAt": "2025-01-01"}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    encoded = source_cwd.replace("/", "-")
    proj_dir = claude_dir / "projects" / encoded
    proj_dir.mkdir(parents=True)
    (proj_dir / f"{session_id}.jsonl").write_text('{"msg":"hello"}\n')

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    builder = BundleBuilder(Manifest(
        session_id=session_id, source_cwd=source_cwd, provider="claude_code"
    ))
    provider.export_session(session_id, builder)
    data = builder.build()

    # Import to different CWD
    target_claude = tmp_path / "target-claude"
    target_provider = ClaudeCodeProvider(base_dir=target_claude)
    reader = BundleReader(data)
    target_provider.import_session(reader, target_dir="/home/target/project")

    sessions = target_provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].cwd == "/home/target/project"

    # Check that project dir was rewritten
    target_encoded = "/home/target/project".replace("/", "-")
    assert (target_claude / "projects" / target_encoded / f"{session_id}.jsonl").exists()
    reader.close()


def test_claude_find_session_malformed(tmp_path):
    """_find_session_file skips malformed files and returns None for not found."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    (sessions_dir / "bad.json").write_text("not json")
    (sessions_dir / "other.json").write_text(json.dumps({
        "pid": 1, "sessionId": "other-id", "cwd": "/tmp", "startedAt": "2025-01-01"
    }))

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    # Searching for non-matching ID — covers the loop + return None
    path, data = provider._find_session_file("nonexistent-session")
    assert path is None
    assert data == {}
