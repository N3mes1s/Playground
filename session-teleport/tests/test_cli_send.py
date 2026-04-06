"""Tests for CLI send command."""

import json
import os
import subprocess
import threading
from http.server import HTTPServer

from click.testing import CliRunner

from session_teleport.cli import main
from session_teleport.transfer.relay import RelayHandler, _bundles

runner = CliRunner()


def test_cli_send_file_method(tmp_claude_dir, tmp_path, monkeypatch):
    """send with --method file should produce a bundle."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "file", "--no-encrypt",
    ])
    assert result.exit_code == 0
    assert "Bundle saved" in result.output


def test_cli_send_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: tmp_path / "none",
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: tmp_path / "none2",
    )
    result = runner.invoke(main, ["send", "nonexistent", "--no-encrypt"])
    assert result.exit_code == 1


def test_cli_send_peer_missing_host(tmp_claude_dir, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "peer", "--no-encrypt",
    ])
    assert result.exit_code == 1
    assert "host" in result.output.lower()


def test_cli_send_relay_missing_url(tmp_claude_dir, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "relay", "--no-encrypt",
    ])
    assert result.exit_code == 1
    assert "relay" in result.output.lower()


def test_cli_send_relay_method(tmp_claude_dir, tmp_path, monkeypatch):
    """Send via relay to a real relay server."""
    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        claude_dir, session_id, cwd = tmp_claude_dir
        monkeypatch.setattr(
            "session_teleport.providers.claude_code.get_claude_dir",
            lambda: claude_dir,
        )
        monkeypatch.setattr(
            "session_teleport.providers.codex_cli.get_codex_dir",
            lambda: claude_dir.parent / "no-codex",
        )
        result = runner.invoke(main, [
            "send", session_id[:8], "--method", "relay", "--no-encrypt",
            "--relay-url", f"http://127.0.0.1:{port}",
        ])
        assert result.exit_code == 0
        assert "pickup code" in result.output.lower() or "code" in result.output.lower()
    finally:
        server.shutdown()
        _bundles.clear()


def test_cli_send_file_encrypted(tmp_claude_dir, tmp_path, monkeypatch):
    """Send with encryption enabled."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "file",
    ], input="testpass\ntestpass\n")
    assert result.exit_code == 0


def test_cli_send_encrypt_prompt(tmp_claude_dir, tmp_path, monkeypatch):
    """Send with default encrypt=True to cover passphrase prompt."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "file", "--encrypt",
    ], input="pw\npw\n")
    assert result.exit_code == 0


def test_cli_send_peer_method(tmp_claude_dir, tmp_path, monkeypatch):
    """Send via peer method with mocked send_to_peer."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir",
        lambda: claude_dir.parent / "no-codex",
    )

    async def mock_send(data, host, port, auth_code):
        pass

    monkeypatch.setattr(
        "session_teleport.cli.send_cmd.send_to_peer", mock_send
    )

    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "peer", "--no-encrypt",
        "--host", "127.0.0.1", "--port", "9999",
    ], input="123456\n")
    assert result.exit_code == 0


def test_cli_send_with_git_files(tmp_path, monkeypatch):
    """Send covers git capture when cwd is a git repo."""
    env = {
        **os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"
    }
    cwd = tmp_path / "project"
    cwd.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=cwd, capture_output=True, env=env
    )
    subprocess.run(
        ["git", "config", "user.email", "t@t"], cwd=cwd, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.name", "T"], cwd=cwd, capture_output=True
    )
    subprocess.run(
        ["git", "config", "commit.gpgsign", "false"],
        cwd=cwd, capture_output=True,
    )
    (cwd / "f.txt").write_text("x\n")
    subprocess.run(["git", "add", "."], cwd=cwd, capture_output=True, env=env)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=cwd, capture_output=True, env=env
    )

    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "send-git-test"
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
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "file", "--no-encrypt",
    ])
    assert result.exit_code == 0
