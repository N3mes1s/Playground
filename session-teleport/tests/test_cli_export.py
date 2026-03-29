"""Tests for CLI export command."""

import json
import os
import subprocess
from pathlib import Path

from click.testing import CliRunner

from session_teleport.cli import main

runner = CliRunner()


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
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--no-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0, result.output
    assert "Bundle saved" in result.output

    result = runner.invoke(main, ["inspect", output_path])
    assert result.exit_code == 0
    assert "claude_code" in result.output
    assert "Bundle Info" in result.output


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

    result = runner.invoke(main, ["inspect", output_path])
    assert result.exit_code == 0
    assert "python" in result.output.lower() or "Tool versions" in result.output


def test_cli_export_with_git(tmp_claude_dir, tmp_path, monkeypatch):
    """Export with --include-git for a non-git cwd."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    output_path = str(tmp_path / "with-git.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--include-git", "--include-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0


def test_cli_export_auto_output_name(tmp_claude_dir, tmp_path, monkeypatch):
    """Export without -o should auto-generate filename."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--no-git", "--no-env",
    ])
    assert result.exit_code == 0
    assert f"session-{session_id[:8]}.stp" in result.output


def test_cli_export_with_real_git(tmp_path, monkeypatch):
    """Export with --include-git on a real git repo."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    cwd = tmp_path / "project"
    cwd.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=cwd, capture_output=True)
    subprocess.run(
        ["git", "config", "commit.gpgsign", "false"],
        cwd=cwd, capture_output=True,
    )
    (cwd / "main.py").write_text("print('hi')\n")
    subprocess.run(["git", "add", "."], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=cwd, capture_output=True, env=env)

    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "git-export-test"
    meta = {
        "pid": 1, "sessionId": session_id,
        "cwd": str(cwd), "startedAt": "2025-01-01",
    }
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    encoded = str(cwd).replace("/", "-")
    proj_dir = claude_dir / "projects" / encoded
    proj_dir.mkdir(parents=True)
    (proj_dir / f"{session_id}.jsonl").write_text('{"msg":"test"}\n')

    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )

    output_path = str(tmp_path / "git-export.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--include-git", "--no-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0
    assert Path(output_path).exists()


def test_cli_export_secrets_cancel(tmp_path, monkeypatch):
    """Export cancelled when secrets detected and user declines."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)

    session_id = "secret-test-1234"
    cwd = str(tmp_path / "proj")
    meta = {
        "pid": 1, "sessionId": session_id,
        "cwd": cwd, "startedAt": "2025-01-01",
    }
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    encoded_cwd = cwd.replace("/", "-")
    proj_dir = claude_dir / "projects" / encoded_cwd
    proj_dir.mkdir(parents=True)
    secret_line = json.dumps({
        "content": "Here is the key: sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    })
    (proj_dir / f"{session_id}.jsonl").write_text(secret_line + "\n")

    (tmp_path / "proj").mkdir(exist_ok=True)

    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--no-git", "--no-env",
        "-o", str(tmp_path / "out.stp"),
    ], input="n\n")
    assert result.exit_code == 1 or "cancelled" in result.output.lower()
