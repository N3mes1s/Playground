"""Tests for Claude Code provider."""

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
