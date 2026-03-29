"""Tests for collectors: git_state, env_snapshot, tool_versions."""

import json
import os
import subprocess
from unittest.mock import patch

from session_teleport.collectors.env_snapshot import capture_env, restore_env_info
from session_teleport.collectors.git_state import apply_git_state, capture_git_state
from session_teleport.collectors.tool_versions import capture_tool_versions

# --- git_state ---

def test_capture_git_state_not_a_repo(tmp_path):
    """Non-git directory returns empty dict."""
    result = capture_git_state(str(tmp_path))
    assert result == {}


def _init_test_repo(tmp_path):
    """Create a minimal git repo with one commit. Returns repo path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@test.com"}
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
    return repo, env


def test_capture_git_state_real_repo(tmp_path):
    """Capture git state from a minimal git repo."""
    repo, env = _init_test_repo(tmp_path)

    (repo / "file.txt").write_text("hello")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env)

    result = capture_git_state(str(repo))
    assert "git/branch.txt" in result
    assert "git/commit.txt" in result
    assert "git/log.txt" in result
    assert b"init" in result["git/log.txt"]


def test_capture_git_state_with_uncommitted_changes(tmp_path):
    """Uncommitted changes should produce a diff patch."""
    repo, env = _init_test_repo(tmp_path)

    (repo / "file.txt").write_text("original")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env)

    # Make uncommitted change
    (repo / "file.txt").write_text("modified")

    result = capture_git_state(str(repo))
    assert "git/uncommitted.patch" in result
    assert b"modified" in result["git/uncommitted.patch"]
    assert "git/status.txt" in result


def test_apply_git_state_dry_run(tmp_path):
    """Dry run should report actions without modifying anything."""
    from session_teleport.core.bundle import BundleBuilder, BundleReader
    from session_teleport.core.manifest import Manifest

    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    builder.add_file("git/remote.txt", b"https://github.com/test/repo.git")
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state(str(tmp_path), reader, dry_run=True)
    assert any("main" in a for a in actions)
    assert any("abc123" in a for a in actions)
    reader.close()


def test_apply_git_state_no_git_data(tmp_path):
    """No git files in bundle means no actions."""
    from session_teleport.core.bundle import BundleBuilder, BundleReader
    from session_teleport.core.manifest import Manifest

    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"no git here")
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state(str(tmp_path), reader)
    assert len(actions) == 0
    reader.close()


# --- env_snapshot ---

def test_capture_env():
    """Should capture env vars and redact secrets."""
    result = capture_env()
    assert "env/filtered_env.json" in result
    assert "env/redacted_names.json" in result

    env = json.loads(result["env/filtered_env.json"])
    assert "PATH" in env  # PATH should always be present

    redacted = json.loads(result["env/redacted_names.json"])
    assert isinstance(redacted, list)


def test_capture_env_redacts_secrets():
    """Known secret env vars should be redacted."""
    fake_env = {
        "PATH": "/usr/bin",
        "HOME": "/home/user",
        "OPENAI_API_KEY": "sk-fake-key-1234567890",
        "MY_SECRET": "supersecret",
    }
    with patch.dict(os.environ, fake_env, clear=True):
        result = capture_env()
        env = json.loads(result["env/filtered_env.json"])
        redacted = json.loads(result["env/redacted_names.json"])

        assert "PATH" in env
        assert "OPENAI_API_KEY" not in env
        assert "OPENAI_API_KEY" in redacted


def test_restore_env_info():
    """Should read env from a bundle."""
    from session_teleport.core.bundle import BundleBuilder, BundleReader
    from session_teleport.core.manifest import Manifest

    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("env/filtered_env.json", json.dumps({"FOO": "bar"}).encode())
    data = builder.build()
    reader = BundleReader(data)

    env = restore_env_info(reader)
    assert env == {"FOO": "bar"}
    reader.close()


def test_restore_env_info_missing():
    """Missing env file should return empty dict."""
    from session_teleport.core.bundle import BundleBuilder, BundleReader
    from session_teleport.core.manifest import Manifest

    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"no env")
    data = builder.build()
    reader = BundleReader(data)

    env = restore_env_info(reader)
    assert env == {}
    reader.close()


# --- tool_versions ---

def test_capture_tool_versions():
    """Should capture at least python and git versions."""
    result = capture_tool_versions()
    assert "env/tool_versions.json" in result

    versions = json.loads(result["env/tool_versions.json"])
    assert "python" in versions
    assert "Python" in versions["python"]
    assert "git" in versions
