"""Tests for CLI import command."""

import json
import os
import subprocess

from click.testing import CliRunner

from session_teleport.cli import main
from session_teleport.core.bundle import BundleBuilder
from session_teleport.core.manifest import Manifest

runner = CliRunner()


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

    import_claude = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir",
        lambda: import_claude,
    )

    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0
    assert "imported" in result.output.lower()
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


def test_cli_import_dry_run_coverage(tmp_claude_dir, tmp_path, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "dry.stp")
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--no-env", "-o", output_path,
    ])
    assert result.exit_code == 0

    result = runner.invoke(main, ["import", output_path, "--dry-run"])
    assert result.exit_code == 0
    assert "Dry run" in result.output


def test_cli_import_with_env(tmp_claude_dir, tmp_path, monkeypatch):
    claude_dir, session_id, cwd = tmp_claude_dir
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: claude_dir
    )
    output_path = str(tmp_path / "env.stp")
    result = runner.invoke(main, [
        "export", session_id[:8],
        "--no-encrypt", "--no-git", "--include-env", "-o", output_path,
    ])
    assert result.exit_code == 0

    import_claude = tmp_path / "import-claude"
    monkeypatch.setattr(
        "session_teleport.providers.claude_code.get_claude_dir", lambda: import_claude
    )
    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0


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
    result = runner.invoke(
        main, ["import", output_path, "--no-apply-git"], input="mypass\n"
    )
    assert result.exit_code == 0


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


def test_cli_import_unknown_provider(tmp_path):
    """Import a bundle with unknown provider should error."""
    manifest = Manifest(provider="unknown_provider", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"data")
    bundle_data = builder.build()

    bundle_path = tmp_path / "unknown.stp"
    bundle_path.write_bytes(bundle_data)

    result = runner.invoke(main, ["import", str(bundle_path)])
    assert result.exit_code == 1
    assert "Unknown provider" in result.output


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
    result = runner.invoke(main, ["import", output_path, "--no-apply-git"])
    assert result.exit_code == 0


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
        "pid": 1, "sessionId": "git-apply-test",
        "cwd": str(tmp_path / "src"), "startedAt": "2025-01-01",
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
    result = runner.invoke(main, ["import", str(bundle_path)], input="n\n")
    assert result.exit_code == 0


def test_cli_import_apply_git_yes_and_env(tmp_path, monkeypatch):
    """Import with --apply-git and env/tool_versions.json."""
    env_data = {
        **os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"
    }
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env_data
    )
    subprocess.run(
        ["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.name", "T"], cwd=repo, capture_output=True
    )
    subprocess.run(
        ["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True
    )
    (repo / "file.txt").write_text("content\n")
    subprocess.run(
        ["git", "add", "."], cwd=repo, capture_output=True, env=env_data
    )
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env_data
    )

    manifest = Manifest(
        provider="claude_code",
        session_id="apply-git-env",
        source_cwd=str(repo),
        components=["session", "git", "env"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/1.json", json.dumps({
        "pid": 1, "sessionId": "apply-git-env",
        "cwd": str(repo), "startedAt": "2025-01-01",
    }).encode())
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    builder.add_file(
        "env/tool_versions.json", json.dumps({"python": "3.11"}).encode()
    )
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
        "cwd": str(tmp_path / "src"), "startedAt": "2025-01-01",
    }).encode())
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
