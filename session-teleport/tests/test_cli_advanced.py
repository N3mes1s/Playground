"""Advanced CLI tests covering send, receive, encrypted flows, and edge cases."""


from click.testing import CliRunner

from session_teleport.cli import main

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


def test_cli_receive_relay_missing_args():
    result = runner.invoke(main, ["receive", "--method", "relay"])
    assert result.exit_code == 1


def test_cli_import_encrypted(tmp_claude_dir, tmp_path, monkeypatch):
    """Export encrypted, then import with passphrase."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )

    output_path = str(tmp_path / "encrypted.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-git", "--no-env", "-o", output_path,
    ], input="testpass\ntestpass\n")
    assert result.exit_code == 0

    # Import with passphrase
    import_claude = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: import_claude,
    )
    result = runner.invoke(main, [
        "import", output_path, "--passphrase", "testpass", "--no-apply-git",
    ])
    assert result.exit_code == 0
    assert "imported" in result.output.lower()


def test_cli_import_with_git_apply_prompt(tmp_claude_dir, tmp_path, monkeypatch):
    """Import with git component should prompt for apply."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )

    output_path = str(tmp_path / "with-git.stp")
    result = runner.invoke(main, [
        "export", session_id[:8], "--no-encrypt", "--include-git", "--no-env",
        "-o", output_path,
    ])
    assert result.exit_code == 0

    import_claude = tmp_path / "import-claude2"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: import_claude,
    )
    # Answer 'n' to the git apply prompt
    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0


def test_cli_import_unknown_provider(tmp_path):
    """Import a bundle with unknown provider should error."""
    from session_teleport.core.bundle import BundleBuilder
    from session_teleport.core.manifest import Manifest

    manifest = Manifest(provider="unknown_provider", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"data")
    bundle_data = builder.build()

    bundle_path = tmp_path / "unknown.stp"
    bundle_path.write_bytes(bundle_data)

    result = runner.invoke(main, ["import", str(bundle_path)])
    assert result.exit_code == 1
    assert "Unknown provider" in result.output


def test_cli_export_with_git(tmp_claude_dir, tmp_path, monkeypatch):
    """Export with --include-git for a non-git cwd."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
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
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
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


def test_cli_inspect_with_git_and_env(tmp_claude_dir, tmp_path, monkeypatch):
    """Inspect a bundle that has git + env data."""
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
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
