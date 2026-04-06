"""Tests for CLI list command."""

from click.testing import CliRunner

from session_teleport.cli import main

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Teleport Claude Code" in result.output
    assert "export" in result.output
    assert "import" in result.output
    assert "list" in result.output


def test_cli_version():
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_list_no_sessions(tmp_path, monkeypatch):
    """List with no provider data should warn."""
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: tmp_path / "no-claude",
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: tmp_path / "no-codex",
    )
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "not found" in result.output or "No sessions" in result.output


def test_cli_list_with_claude_session(tmp_claude_dir, monkeypatch):
    """List should show Claude sessions."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "claude_code" in result.output


def test_cli_list_provider_filter(tmp_claude_dir, monkeypatch):
    """List with --provider should filter."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    result = runner.invoke(main, ["list", "--provider", "claude"])
    assert result.exit_code == 0
    assert "claude_code" in result.output


def test_cli_list_specific_provider(tmp_claude_dir, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    result = runner.invoke(main, ["list", "--provider", "claude"])
    assert result.exit_code == 0


def test_cli_list_no_sessions_all(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: tmp_path / "no"
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir", lambda: tmp_path / "no2"
    )
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "No sessions found" in result.output or "not found" in result.output
