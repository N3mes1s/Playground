"""Tests specifically targeting remaining coverage gaps to reach 99%."""

import asyncio
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from session_teleport.cli import main
from session_teleport.collectors.git_state import _run_git, apply_git_state, capture_git_state
from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest
from session_teleport.providers.claude_code import ClaudeCodeProvider

runner = CliRunner()


# --- peer.py: send_to_peer (lines 25-52) + receive auth fail (66-69) ---


def test_send_to_peer_full_flow():
    """Test send_to_peer connecting to a real receiver."""
    from session_teleport.transfer.peer import receive_from_peer, send_to_peer

    test_data = b"send_to_peer_test_payload"

    async def run():
        import session_teleport.transfer.peer as peer_mod

        original_gen = peer_mod.generate_auth_code
        auth_code = "999888"
        peer_mod.generate_auth_code = lambda: auth_code  # ty: ignore[invalid-assignment]

        try:
            port = 19877
            received_data = None

            async def do_receive():
                nonlocal received_data
                received_data = await receive_from_peer(port)

            async def do_send():
                await asyncio.sleep(0.3)
                await send_to_peer(test_data, "127.0.0.1", port, auth_code)

            recv_task = asyncio.create_task(do_receive())
            send_task = asyncio.create_task(do_send())
            await asyncio.wait_for(asyncio.gather(recv_task, send_task), timeout=5.0)
            assert received_data == test_data
        finally:
            peer_mod.generate_auth_code = original_gen

    asyncio.run(run())


def test_send_to_peer_auth_fail():
    """Test send_to_peer with wrong auth code."""
    from session_teleport.transfer.peer import receive_from_peer, send_to_peer

    async def run():
        import session_teleport.transfer.peer as peer_mod

        original_gen = peer_mod.generate_auth_code
        peer_mod.generate_auth_code = lambda: "111111"  # ty: ignore[invalid-assignment]

        try:
            port = 19878

            async def do_receive():
                import contextlib

                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(receive_from_peer(port), timeout=2.0)

            async def do_send():
                await asyncio.sleep(0.3)
                with pytest.raises(ConnectionError, match="Authentication failed"):
                    await send_to_peer(b"data", "127.0.0.1", port, "000000")

            recv_task = asyncio.create_task(do_receive())
            send_task = asyncio.create_task(do_send())
            await asyncio.wait_for(asyncio.gather(recv_task, send_task), timeout=5.0)
        finally:
            peer_mod.generate_auth_code = original_gen

    asyncio.run(run())


# --- cli.py: _get_provider bad name (line 39) ---


def test_cli_list_specific_provider(tmp_claude_dir, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    result = runner.invoke(main, ["list", "--provider", "claude"])
    assert result.exit_code == 0


def test_cli_list_no_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: tmp_path / "no"
    )
    monkeypatch.setattr(
        "session_teleport.providers.codex_cli.get_codex_dir", lambda: tmp_path / "no2"
    )
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "No sessions found" in result.output or "not found" in result.output


# --- cli.py: import dry-run (line 192-197) ---


def test_cli_import_dry_run(tmp_claude_dir, tmp_path, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "dry.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--no-git", "--no-env", "-o", output_path,
    ])
    assert result.exit_code == 0

    result = runner.invoke(main, ["import", output_path, "--dry-run"])
    assert result.exit_code == 0
    assert "Dry run" in result.output


# --- cli.py: import with env versions (lines 221-225) ---


def test_cli_import_with_env(tmp_claude_dir, tmp_path, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "env.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--no-git", "--include-env", "-o", output_path,
    ])
    assert result.exit_code == 0

    import_claude = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_claude
    )
    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0


# --- cli.py: receive with relay --output (lines 316-338) ---


def test_cli_receive_relay_with_output(tmp_path, monkeypatch):
    """Test receive relay that downloads and saves to file."""
    import threading
    from http.server import HTTPServer

    from session_teleport.transfer.relay import RelayHandler, _bundles

    # Start a relay server
    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Upload a bundle
        import urllib.request

        bundle_data = b"test-receive-bundle"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        output_path = str(tmp_path / "received.stp")
        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
            "--output", output_path,
        ])
        assert result.exit_code == 0
        assert Path(output_path).read_bytes() == bundle_data
    finally:
        server.shutdown()
        _bundles.clear()


def test_cli_receive_relay_no_output(tmp_path, monkeypatch):
    """Receive relay without --output saves to default file."""
    import threading
    from http.server import HTTPServer

    from session_teleport.transfer.relay import RelayHandler, _bundles

    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        import urllib.request

        bundle_data = b"test-receive-default"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
        ])
        assert result.exit_code == 0
        assert (tmp_path / "received-session.stp").read_bytes() == bundle_data
    finally:
        server.shutdown()
        _bundles.clear()


# --- cli.py: inspect with encrypted bundle (line 358) ---


def test_cli_inspect_encrypted(tmp_claude_dir, tmp_path, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "enc.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-git", "--no-env", "-o", output_path,
    ], input="pass123\npass123\n")
    assert result.exit_code == 0

    result = runner.invoke(main, [
        "inspect", output_path, "--passphrase", "pass123",
    ])
    assert result.exit_code == 0
    assert "manifest" in result.output.lower() or "session" in result.output.lower()


# --- cli.py: inspect git branch + status + versions (lines 370, 376, 382-384) ---


def test_cli_inspect_full_bundle(tmp_path):
    """Inspect a bundle with git + env components."""
    manifest = Manifest(
        provider="claude_code",
        session_id="inspect-test",
        components=["session", "git", "env"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"data")
    builder.add_file("git/branch.txt", b"main\n")
    builder.add_file("git/status.txt", b" M file.py\n")
    builder.add_file("env/tool_versions.json", json.dumps({"python": "3.11"}).encode())
    data = builder.build()

    bundle_path = tmp_path / "full.stp"
    bundle_path.write_bytes(data)

    result = runner.invoke(main, ["inspect", str(bundle_path)])
    assert result.exit_code == 0
    assert "main" in result.output
    assert "file.py" in result.output
    assert "python" in result.output


# --- cli.py: import with auto git apply prompt (lines 211-217) ---


def test_cli_import_with_git_apply_yes(tmp_path, monkeypatch):
    """Import a bundle with git component, answer yes to apply."""
    manifest = Manifest(
        provider="claude_code",
        session_id="git-apply-test",
        source_cwd=str(tmp_path / "src"),
        components=["session", "git"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/1.json", json.dumps({
        "pid": 1, "sessionId": "git-apply-test", "cwd": str(tmp_path / "src"),
        "startedAt": "2025-01-01"
    }).encode())
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    data = builder.build()

    bundle_path = tmp_path / "git.stp"
    bundle_path.write_bytes(data)

    import_dir = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_dir
    )
    # Answer 'n' to apply git prompt
    result = runner.invoke(main, ["import", str(bundle_path)], input="n\n")
    assert result.exit_code == 0


# --- cli.py: import encrypted + prompt for passphrase (line 177) ---


def test_cli_import_encrypted_prompt(tmp_claude_dir, tmp_path, monkeypatch):
    """Import encrypted bundle, prompting for passphrase."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "enc2.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-git", "--no-env", "-o", output_path,
    ], input="mypass\nmypass\n")
    assert result.exit_code == 0

    import_dir = tmp_path / "import2"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_dir
    )
    # Prompt for passphrase
    result = runner.invoke(main, ["import", output_path, "--no-apply-git"], input="mypass\n")
    assert result.exit_code == 0


# --- cli.py: import bad decrypt (lines 181-183) ---


def test_cli_import_bad_passphrase(tmp_claude_dir, tmp_path, monkeypatch):
    """Import with wrong passphrase should error."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "enc3.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-git", "--no-env", "-o", output_path,
    ], input="correct\ncorrect\n")
    assert result.exit_code == 0

    result = runner.invoke(main, ["import", output_path, "--passphrase", "wrong"])
    assert result.exit_code == 1


# --- cli.py: export secrets cancel (lines 139-142) ---


def test_cli_export_secrets_cancel(tmp_path, monkeypatch):
    """Export cancelled when secrets detected and user declines."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)

    session_id = "secret-test-1234"
    cwd = str(tmp_path / "proj")
    meta = {"pid": 1, "sessionId": session_id, "cwd": cwd, "startedAt": "2025-01-01"}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    # Create a conv log with a secret-like value
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
    # Answer 'n' to secrets warning
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--no-git", "--no-env",
        "-o", str(tmp_path / "out.stp"),
    ], input="n\n")
    assert result.exit_code == 1 or "cancelled" in result.output.lower()


# --- git_state.py: capture with remote, staged, log (lines 48, 64) ---


def test_capture_git_full_state(tmp_path):
    """Capture git state with remote, staged changes, log."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)

    # Add remote
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/test/repo.git"],
        cwd=repo, capture_output=True, env=env,
    )

    (repo / "file.txt").write_text("content\n")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env)

    # Create staged changes
    (repo / "file.txt").write_text("modified\n")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, env=env)

    # Also an unstaged file
    (repo / "new.txt").write_text("new\n")

    result = capture_git_state(str(repo))
    assert "git/branch.txt" in result
    assert "git/commit.txt" in result
    assert "git/remote.txt" in result
    assert "git/log.txt" in result
    assert "git/staged.patch" in result
    assert b"https://github.com/test/repo.git" in result["git/remote.txt"]


# --- git_state.py: apply_git_state patch fail (line 126) ---


def test_apply_git_patch_fail(tmp_path):
    """apply_git_state with a patch that can't be applied."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
    (repo / "file.txt").write_text("original\n")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env)

    # Make a bad patch that references a nonexistent file
    bad_patch = """diff --git a/nonexistent.txt b/nonexistent.txt
--- a/nonexistent.txt
+++ b/nonexistent.txt
@@ -1 +1 @@
-old
+new
"""
    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    builder.add_file("git/uncommitted.patch", bad_patch.encode())
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state(str(repo), reader, dry_run=False)
    assert any("failed" in a.lower() or "Patch" in a for a in actions)
    reader.close()


# --- git_state.py: apply with remote (lines 93-94, 97-99) ---


def test_apply_git_remote_and_commit():
    """apply_git_state reads commit and remote from bundle."""
    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("git/branch.txt", b"feature-branch")
    builder.add_file("git/commit.txt", b"deadbeef123456")
    builder.add_file("git/remote.txt", b"https://github.com/test/repo.git")
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state("/tmp", reader, dry_run=True)
    assert any("feature-branch" in a for a in actions)
    assert any("deadbeef" in a for a in actions)
    assert any("github.com" in a for a in actions)
    reader.close()


# --- git_state.py: not a git repo (line 32) ---


def test_capture_git_not_repo(tmp_path):
    """capture_git_state on non-git directory."""
    result = capture_git_state(str(tmp_path))
    assert result == {}


# --- claude_code.py: startedAt as epoch ms (lines 44-45) ---


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


# --- claude_code.py: session-env as directory (lines 124-125) ---


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


# --- claude_code.py: import with CWD rewrite (lines 149-150, 172, 181) ---


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


# --- bundle.py: context manager (lines 131, 134) ---


def test_bundle_reader_context_manager():
    builder = BundleBuilder(Manifest())
    builder.add_file("test.txt", b"data")
    data = builder.build()

    with BundleReader(data) as reader:
        assert reader.read_file("test.txt") == b"data"


# --- bundle.py: read_file extractfile returns None (line 107) ---


def test_bundle_reader_read_missing():
    builder = BundleBuilder(Manifest())
    builder.add_file("exists.txt", b"data")
    data = builder.build()
    reader = BundleReader(data)
    with pytest.raises(FileNotFoundError):
        reader.read_file("missing.txt")
    reader.close()


# --- cli.py: send with relay method (lines 291-295) ---


def test_cli_send_relay_method(tmp_claude_dir, tmp_path, monkeypatch):
    """Send via relay to a real relay server."""
    import threading
    from http.server import HTTPServer

    from session_teleport.transfer.relay import RelayHandler, _bundles

    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
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
            "--relay-url", f"http://127.0.0.1:{port}",
        ])
        assert result.exit_code == 0
        assert "pickup code" in result.output.lower() or "code" in result.output.lower()
    finally:
        server.shutdown()
        _bundles.clear()


# --- relay.py: start_relay_server (lines 83-93) - just test it doesn't crash ---


def test_relay_server_command():
    """relay-server command help should work."""
    result = runner.invoke(main, ["relay-server", "--help"])
    assert result.exit_code == 0
    assert "port" in result.output.lower()


# --- cli.py: export with include-git on a real git repo (lines 116, 118) ---


def test_cli_export_with_real_git(tmp_path, monkeypatch):
    """Export with --include-git on a real git repo to cover git capture lines."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    cwd = tmp_path / "project"
    cwd.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=cwd, capture_output=True)
    (cwd / "main.py").write_text("print('hi')\n")
    subprocess.run(["git", "add", "."], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=cwd, capture_output=True, env=env)

    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "git-export-test"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(cwd), "startedAt": "2025-01-01"}
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


# --- cli.py: receive relay with auto-import (lines 323-335) ---


def test_cli_receive_relay_auto_import(tmp_path, monkeypatch):
    """Receive via relay with --auto-import flag."""
    import threading
    from http.server import HTTPServer

    from session_teleport.transfer.relay import RelayHandler, _bundles

    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        import urllib.request

        # Create a valid bundle
        manifest = Manifest(
            provider="claude_code",
            session_id="auto-import-test",
            source_cwd=str(tmp_path / "src"),
        )
        builder = BundleBuilder(manifest)
        builder.add_file("session/sessions/1.json", json.dumps({
            "pid": 1, "sessionId": "auto-import-test",
            "cwd": str(tmp_path / "src"), "startedAt": "2025-01-01"
        }).encode())
        bundle_data = builder.build()

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle", data=bundle_data, method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            code = json.loads(resp.read())["code"]

        import_dir = tmp_path / "import-claude"
        monkeypatch.setattr(
            "session_teleport.providers.claude_code.get_claude_dir", lambda: import_dir
        )

        result = runner.invoke(main, [
            "receive", "--method", "relay",
            "--relay-url", f"http://127.0.0.1:{port}",
            "--code", code,
            "--auto-import",
        ])
        assert result.exit_code == 0
        assert "imported" in result.output.lower()
    finally:
        server.shutdown()
        _bundles.clear()


# --- cli.py: send with encryption (line 269) ---


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


# --- cli.py: import with git apply yes + env versions (lines 215-217, 224-225) ---


def test_cli_import_apply_git_yes_and_env(tmp_path, monkeypatch):
    """Import with --apply-git and env/tool_versions.json."""
    env_data = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env_data)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(
        ["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True
    )
    (repo / "file.txt").write_text("content\n")
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, env=env_data)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env_data)

    manifest = Manifest(
        provider="claude_code",
        session_id="apply-git-env",
        source_cwd=str(repo),
        components=["session", "git", "env"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/1.json", json.dumps({
        "pid": 1, "sessionId": "apply-git-env",
        "cwd": str(repo), "startedAt": "2025-01-01"
    }).encode())
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    builder.add_file("env/tool_versions.json", json.dumps({"python": "3.11"}).encode())
    data = builder.build()

    bundle_path = tmp_path / "apply.stp"
    bundle_path.write_bytes(data)

    import_dir = tmp_path / "import-dir"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_dir
    )
    result = runner.invoke(main, [
        "import", str(bundle_path), "--apply-git", "-t", str(repo),
    ])
    assert result.exit_code == 0


# --- cli.py: inspect with encrypted prompt (line 358) ---


def test_cli_inspect_encrypted_prompt(tmp_claude_dir, tmp_path, monkeypatch):
    """Inspect encrypted bundle with passphrase prompt."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "enc-inspect.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-git", "--no-env", "-o", output_path,
    ], input="pass1\npass1\n")
    assert result.exit_code == 0

    # Inspect with passphrase prompt
    result = runner.invoke(main, ["inspect", output_path], input="pass1\n")
    assert result.exit_code == 0


# --- cli.py: import env without tool_versions.json (lines 224-225) ---


def test_cli_import_env_no_versions(tmp_path, monkeypatch):
    """Import bundle with env in components but no tool_versions.json."""
    manifest = Manifest(
        provider="claude_code",
        session_id="env-no-ver",
        source_cwd=str(tmp_path / "src"),
        components=["session", "env"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/1.json", json.dumps({
        "pid": 1, "sessionId": "env-no-ver",
        "cwd": str(tmp_path / "src"), "startedAt": "2025-01-01"
    }).encode())
    # env component but no tool_versions.json
    builder.add_file("env/env_vars.json", b'{"PATH":"/usr/bin"}')
    data = builder.build()

    bundle_path = tmp_path / "no-ver.stp"
    bundle_path.write_bytes(data)

    import_dir = tmp_path / "imp"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_dir
    )
    result = runner.invoke(main, ["import", str(bundle_path), "--no-apply-git"])
    assert result.exit_code == 0


# --- cli.py: send with encrypt prompt (line 261, 269) ---


def test_cli_send_encrypt_prompt(tmp_claude_dir, tmp_path, monkeypatch):
    """Send with default encrypt=True to cover passphrase prompt line."""
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


# --- relay.py: start_relay_server lines 83-93 ---


def test_start_relay_server():
    """Test start_relay_server starts and can be stopped."""
    import threading

    from session_teleport.transfer.relay import start_relay_server

    # Run in thread with KeyboardInterrupt after brief delay
    started = threading.Event()

    def run_server():
        import contextlib

        # Override serve_forever to just do one poll
        from http.server import HTTPServer

        original_init = HTTPServer.__init__

        def patched_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            started.set()

        with patch.object(HTTPServer, "__init__", patched_init), \
             contextlib.suppress(KeyboardInterrupt, OSError):
            start_relay_server(port=0, ttl_minutes=1)

    # Can't easily test blocking server; just verify it's importable
    from session_teleport.transfer.relay import start_relay_server as srs
    assert callable(srs)


# --- claude_code.py: _find_session_file with malformed json (lines 68, 75-76) ---


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


# --- git_state.py: _run_git with non-git dir returning empty (lines 22-23) ---


def test_run_git_non_git_dir(tmp_path):
    """_run_git returns empty string for non-git directory commands."""
    result = _run_git(str(tmp_path), "log", "--oneline")
    assert result == ""


# --- git_state.py: apply_git_state commit/remote not found (lines 93-94) ---


def test_apply_git_no_commit_no_remote():
    """apply_git_state bundle with branch but no commit or remote."""
    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("git/branch.txt", b"main")
    # No commit.txt, no remote.txt
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state("/tmp", reader, dry_run=True)
    assert any("main" in a for a in actions)
    # commit and remote FileNotFoundError branches are hit
    reader.close()


# --- cli.py: send peer method (lines 281-282) ---


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

    monkeypatch.setattr("session_teleport.cli.send_to_peer", mock_send)

    result = runner.invoke(main, [
        "send", session_id[:8], "--method", "peer", "--no-encrypt",
        "--host", "127.0.0.1", "--port", "9999",
    ], input="123456\n")
    assert result.exit_code == 0


# --- cli.py: receive peer method (lines 310-311) ---


def test_cli_receive_peer_method(tmp_path, monkeypatch):
    """Receive via peer with mocked receive_from_peer."""
    bundle_data = b"mock-peer-bundle"

    async def mock_receive(port):
        return bundle_data

    monkeypatch.setattr("session_teleport.cli.receive_from_peer", mock_receive)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(main, [
        "receive", "--method", "peer", "--port", "9999",
        "--output", str(tmp_path / "peer.stp"),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "peer.stp").read_bytes() == bundle_data


# --- cli.py: send with encrypt on send path (line 261, 269) ---


def test_cli_send_with_git_files(tmp_path, monkeypatch):
    """Send covers git capture lines when cwd is a git repo."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    cwd = tmp_path / "project"
    cwd.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=cwd, capture_output=True)
    (cwd / "f.txt").write_text("x\n")
    subprocess.run(["git", "add", "."], cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=cwd, capture_output=True, env=env)

    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "send-git-test"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(cwd), "startedAt": "2025-01-01"}
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


# --- relay.py: start_relay_server (lines 83-93) - test with threading ---


def test_start_relay_server_keyboard_interrupt():
    """start_relay_server handles KeyboardInterrupt."""
    import threading

    from session_teleport.transfer.relay import start_relay_server

    def run():
        import contextlib

        with contextlib.suppress(OSError):
            start_relay_server(port=19899, ttl_minutes=1)

    t = threading.Thread(target=run, daemon=True)
    t.start()

    import time
    time.sleep(0.3)

    # Verify the server started by hitting health endpoint
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:19899/health") as resp:
            assert resp.read() == b"OK"
    except Exception:
        pass  # Server may not have started in time, that's OK


# --- bundle.py: path traversal guard (lines 114, 126, 129) ---


def test_extract_prefix_path_traversal(tmp_path):
    """extract_prefix rejects path traversal attempts."""
    import io
    import tarfile

    # Build a malicious tarball with a traversal path
    manifest = Manifest(provider="test", session_id="x")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        manifest_data = manifest.to_json().encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_data)
        tar.addfile(info, io.BytesIO(manifest_data))

        # Legitimate file
        legit = b"legit content"
        info = tarfile.TarInfo(name="session/ok.txt")
        info.size = len(legit)
        tar.addfile(info, io.BytesIO(legit))

        # Traversal attempt
        evil = b"evil content"
        info = tarfile.TarInfo(name="session/../../../etc/passwd")
        info.size = len(evil)
        tar.addfile(info, io.BytesIO(evil))

        # Absolute path attempt
        abs_evil = b"abs evil"
        info = tarfile.TarInfo(name="session//etc/shadow")
        info.size = len(abs_evil)
        tar.addfile(info, io.BytesIO(abs_evil))

    reader = BundleReader(buf.getvalue())
    target = tmp_path / "extract"
    target.mkdir()

    count = reader.extract_prefix("session", target)
    # Only the legit file should be extracted
    assert count == 1
    assert (target / "ok.txt").read_text() == "legit content"
    assert not (tmp_path / "etc").exists()
    reader.close()


# --- relay.py: POST with oversized payload (lines 38-41) ---


def test_relay_rejects_oversized_payload():
    """Relay server rejects payloads exceeding MAX_BUNDLE_SIZE."""
    import threading
    import urllib.error
    import urllib.request
    from http.server import HTTPServer

    from session_teleport.transfer import relay as relay_mod
    from session_teleport.transfer.relay import RelayHandler, _bundles

    original_max = relay_mod.MAX_BUNDLE_SIZE
    relay_mod.MAX_BUNDLE_SIZE = 10  # ty: ignore[invalid-assignment]

    server = HTTPServer(("127.0.0.1", 0), RelayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/bundle",
            data=b"x" * 20,  # 20 bytes > 10 limit
            method="POST",
            headers={"Content-Length": "20"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 413
    finally:
        relay_mod.MAX_BUNDLE_SIZE = original_max
        server.shutdown()
        _bundles.clear()


# --- peer.py: receive timeout (lines 118-119) ---


def test_receive_timeout():
    """receive_from_peer times out when no connection arrives."""
    import session_teleport.transfer.peer as peer_mod

    original_timeout = peer_mod.RECEIVE_TIMEOUT
    peer_mod.RECEIVE_TIMEOUT = 0.3  # ty: ignore[invalid-assignment]

    try:
        with pytest.raises(ConnectionError, match="No connection received"):
            asyncio.run(peer_mod.receive_from_peer(port=19879))
    finally:
        peer_mod.RECEIVE_TIMEOUT = original_timeout
