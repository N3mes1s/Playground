"""Tests for CLI inspect command."""

import json

from click.testing import CliRunner

from session_teleport.cli import main
from session_teleport.core.bundle import BundleBuilder
from session_teleport.core.manifest import Manifest

runner = CliRunner()


def test_cli_inspect_nonexistent():
    """Inspecting nonexistent file should error."""
    result = runner.invoke(main, ["inspect", "/tmp/no-such-file.stp"])
    assert result.exit_code != 0


def test_cli_inspect_with_git_and_env(tmp_claude_dir, tmp_path, monkeypatch):
    """Inspect a bundle that has git + env data."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: claude_dir,
    )

    output_path = str(tmp_path / "full.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--include-git", "--include-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0

    result = runner.invoke(main, ["inspect", output_path])
    assert result.exit_code == 0
    assert "python" in result.output.lower() or "Tool versions" in result.output


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
    builder.add_file(
        "env/tool_versions.json", json.dumps({"python": "3.11"}).encode()
    )
    data = builder.build()

    bundle_path = tmp_path / "full.stp"
    bundle_path.write_bytes(data)

    result = runner.invoke(main, ["inspect", str(bundle_path)])
    assert result.exit_code == 0
    assert "main" in result.output
    assert "file.py" in result.output
    assert "python" in result.output


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

    result = runner.invoke(main, ["inspect", output_path], input="pass1\n")
    assert result.exit_code == 0
