"""Tests for CLI commands using Click's test runner."""

import json

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


def test_cli_export_not_found(tmp_path, monkeypatch):
    """Export with nonexistent session ID should error."""
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: tmp_path / "no-claude",
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: tmp_path / "no-codex",
    )
    result = runner.invoke(main, ["export", "nonexistent"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_cli_export_and_inspect(tmp_claude_dir, tmp_path, monkeypatch):
    """Export a session then inspect the bundle."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )

    output_path = str(tmp_path / "exported.stp")

    # Export without encryption and without git (test dir isn't a git repo)
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--no-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0, result.output
    assert "Bundle saved" in result.output

    # Inspect it
    result = runner.invoke(main, ["inspect", output_path])
    assert result.exit_code == 0
    assert "claude_code" in result.output
    assert "Bundle Info" in result.output


def test_cli_export_and_import(tmp_claude_dir, tmp_path, monkeypatch):
    """Full export then import roundtrip."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )

    output_path = str(tmp_path / "roundtrip.stp")
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--no-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0

    # Import into a fresh claude dir
    import_claude = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: import_claude,
    )

    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0
    assert "imported" in result.output.lower()

    # Verify the session was created
    assert (import_claude / "sessions").exists()


def test_cli_import_dry_run(tmp_claude_dir, tmp_path, monkeypatch):
    """Dry run import should not write files."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )

    output_path = str(tmp_path / "dryrun.stp")
    runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--no-env",
        "-o", output_path,
    ])

    import_dir = tmp_path / "dry-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: import_dir,
    )

    result = runner.invoke(main, ["import", output_path, "--dry-run"])
    assert result.exit_code == 0
    assert "Dry run" in result.output
    assert not import_dir.exists()


def test_cli_inspect_nonexistent():
    """Inspecting nonexistent file should error."""
    result = runner.invoke(main, ["inspect", "/tmp/no-such-file.stp"])
    assert result.exit_code != 0


def test_cli_export_with_env(tmp_claude_dir, tmp_path, monkeypatch):
    """Export with environment capture should include env data."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )

    output_path = str(tmp_path / "with-env.stp")
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--include-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0

    # Inspect should show tool versions
    result = runner.invoke(main, ["inspect", output_path])
    assert result.exit_code == 0
    assert "python" in result.output.lower() or "Tool versions" in result.output
