"""Edge case tests for providers and collectors to fill coverage gaps."""

import json
import os
import subprocess
from pathlib import Path

from session_teleport.collectors.git_state import _run_git, apply_git_state, capture_git_state
from session_teleport.collectors.tool_versions import _get_version
from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest
from session_teleport.providers.claude_code import ClaudeCodeProvider
from session_teleport.providers.codex_cli import (
    CodexCliProvider,
    _parse_rollout_filename,
    _read_session_meta,
)

# --- Claude Code edge cases ---


def test_claude_list_empty_sessions_dir(tmp_path):
    claude_dir = tmp_path / ".claude"
    (claude_dir / "sessions").mkdir(parents=True)
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    assert provider.list_sessions() == []


def test_claude_list_malformed_session_file(tmp_path):
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    (sessions_dir / "bad.json").write_text("not json")
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    assert provider.list_sessions() == []


def test_claude_list_no_sessions_dir(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    assert provider.list_sessions() == []


def test_claude_export_not_found(tmp_path):
    claude_dir = tmp_path / ".claude"
    (claude_dir / "sessions").mkdir(parents=True)
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    import pytest

    with pytest.raises(ValueError, match="not found"):
        builder = BundleBuilder(Manifest())
        provider.export_session("nonexistent", builder)


def test_claude_export_missing_conv_log(tmp_path):
    """Session exists but no conversation log."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "missing-conv-log-1234"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(tmp_path), "startedAt": 1700000000000}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    builder = BundleBuilder(Manifest(session_id=session_id))
    provider.export_session(session_id, builder)
    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()
    assert any("sessions/" in f for f in files)
    reader.close()


def test_claude_export_with_claude_md(tmp_path):
    """Export should include CLAUDE.md if present in cwd."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    cwd = tmp_path / "project"
    cwd.mkdir()
    (cwd / "CLAUDE.md").write_text("# Project instructions\n")

    session_id = "claude-md-test"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(cwd), "startedAt": 1700000000000}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    builder = BundleBuilder(Manifest(session_id=session_id))
    provider.export_session(session_id, builder)
    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()
    assert any("CLAUDE.md" in f for f in files)
    reader.close()


def test_claude_export_session_env_as_file(tmp_path):
    """session-env/{id} as a regular file."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    session_id = "env-file-test"
    meta = {"pid": 1, "sessionId": session_id, "cwd": str(tmp_path), "startedAt": 1700000000000}
    (sessions_dir / "1.json").write_text(json.dumps(meta))

    env_dir = claude_dir / "session-env"
    env_dir.mkdir(parents=True)
    (env_dir / session_id).write_text("env data")

    provider = ClaudeCodeProvider(base_dir=claude_dir)
    builder = BundleBuilder(Manifest(session_id=session_id))
    provider.export_session(session_id, builder)
    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()
    assert any("session-env" in f for f in files)
    reader.close()


def test_claude_import_same_cwd(tmp_claude_dir, tmp_path):
    """Import without target_dir uses source cwd (no rewrite)."""
    claude_dir, session_id, cwd = tmp_claude_dir
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    manifest = Manifest(provider="claude_code", session_id=session_id, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_id, builder)
    data = builder.build()

    target = tmp_path / "target"
    target_provider = ClaudeCodeProvider(base_dir=target)
    reader = BundleReader(data)
    target_provider.import_session(reader, target_dir=None)

    sessions = target_provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].cwd == cwd
    reader.close()


def test_claude_started_at_string(tmp_path):
    """startedAt as an ISO string (not epoch ms)."""
    claude_dir = tmp_path / ".claude"
    sessions_dir = claude_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    meta = {
        "pid": 1,
        "sessionId": "iso-ts-test",
        "cwd": "/tmp",
        "startedAt": "2025-01-01T00:00:00Z",
    }
    (sessions_dir / "1.json").write_text(json.dumps(meta))
    provider = ClaudeCodeProvider(base_dir=claude_dir)
    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].started_at == "2025-01-01T00:00:00Z"


# --- Codex CLI edge cases ---


def test_codex_not_available(tmp_path):
    provider = CodexCliProvider(base_dir=tmp_path / "nonexistent")
    assert not provider.is_available()
    assert provider.list_sessions() == []


def test_codex_export_not_found(tmp_path):
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir()
    provider = CodexCliProvider(base_dir=codex_dir)
    import pytest

    with pytest.raises(ValueError, match="No rollout file"):
        builder = BundleBuilder(Manifest())
        provider.export_session("nonexistent", builder)


def test_codex_export_no_dir():
    import pytest

    provider = CodexCliProvider(base_dir=Path("/tmp/definitely-not-exist"))
    with pytest.raises(ValueError, match="not found"):
        provider.export_session("x", BundleBuilder(Manifest()))


def test_parse_rollout_filename_valid():
    result = _parse_rollout_filename(
        "rollout-2025-05-07T17-24-21-5973b6c0-94b8-487b-a530-2aeb6098ae0e.jsonl"
    )
    assert result is not None
    ts, uuid = result
    assert "2025" in ts
    assert uuid == "5973b6c0-94b8-487b-a530-2aeb6098ae0e"


def test_parse_rollout_filename_invalid():
    assert _parse_rollout_filename("not-a-rollout.jsonl") is None
    assert _parse_rollout_filename("rollout-bad.jsonl") is None


def test_read_session_meta_valid(tmp_path):
    f = tmp_path / "test.jsonl"
    f.write_text(json.dumps({"meta": {"id": "test"}}) + "\n")
    result = _read_session_meta(f)
    assert result is not None
    assert result["meta"]["id"] == "test"


def test_read_session_meta_invalid(tmp_path):
    f = tmp_path / "bad.jsonl"
    f.write_text("not json\n")
    assert _read_session_meta(f) is None


def test_read_session_meta_missing(tmp_path):
    assert _read_session_meta(tmp_path / "missing.jsonl") is None


def test_codex_find_by_meta_id(tmp_codex_dir):
    """Find rollout by embedded meta ID, not filename UUID."""
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)
    # Full UUID match via meta
    path = provider._find_rollout_by_id(session_uuid)
    assert path is not None


def test_codex_archived_sessions(tmp_path):
    codex_dir = tmp_path / ".codex"
    archived = codex_dir / "archived_sessions"
    archived.mkdir(parents=True)

    uuid = "aaaa1111-2222-3333-4444-bbbbccccdddd"
    name = f"rollout-2025-01-01T00-00-00-{uuid}.jsonl"
    meta = {"meta": {"id": uuid, "timestamp": "2025-01-01T00:00:00Z", "cwd": "/tmp"}}
    (archived / name).write_text(json.dumps(meta) + "\n")

    provider = CodexCliProvider(base_dir=codex_dir)
    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].extra is not None
    assert sessions[0].extra["archived"] is True


def test_codex_rewrite_rollout_cwd():
    """Static method for CWD rewriting."""
    meta = {"meta": {"cwd": "/old/path"}}
    line2 = {"type": "msg", "content": "hello"}
    content = (json.dumps(meta) + "\n" + json.dumps(line2) + "\n").encode()

    result = CodexCliProvider._rewrite_rollout_cwd(content, "/old/path", "/new/path")
    first_line = json.loads(result.decode().split("\n")[0])
    assert first_line["meta"]["cwd"] == "/new/path"


def test_codex_rewrite_no_match():
    """CWD rewrite does nothing when source doesn't match."""
    meta = {"meta": {"cwd": "/other"}}
    content = json.dumps(meta).encode()
    result = CodexCliProvider._rewrite_rollout_cwd(content, "/old", "/new")
    first_line = json.loads(result.decode())
    assert first_line["meta"]["cwd"] == "/other"


def test_codex_rewrite_bad_json():
    content = b"not json at all"
    result = CodexCliProvider._rewrite_rollout_cwd(content, "/a", "/b")
    assert result == content


def test_codex_export_with_memories(tmp_path):
    codex_dir = tmp_path / ".codex"
    sessions_dir = codex_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    memories_dir = codex_dir / "memories"
    memories_dir.mkdir(parents=True)
    (memories_dir / "raw_memories.md").write_text("# Memory\n")

    uuid = "mem-test-1111-2222-3333-444455556666"
    name = f"rollout-2025-01-01T00-00-00-{uuid}.jsonl"
    meta = {"meta": {"id": uuid, "timestamp": "2025-01-01T00:00:00Z"}}
    (sessions_dir / name).write_text(json.dumps(meta) + "\n")

    provider = CodexCliProvider(base_dir=codex_dir)
    builder = BundleBuilder(Manifest(session_id=uuid))
    provider.export_session(uuid, builder)
    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()
    assert any("memories" in f for f in files)
    reader.close()


# --- git_state edge cases ---


def test_run_git_timeout(tmp_path):
    """_run_git should return empty string on timeout or missing command."""
    result = _run_git(str(tmp_path), "nonexistent-command")
    assert result == ""


def test_apply_git_with_patch(tmp_path):
    """apply_git_state with an actual applicable patch."""
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

    # Create a patch
    (repo / "file.txt").write_text("modified\n")
    patch_result = subprocess.run(
        ["git", "diff", "HEAD"], cwd=repo, capture_output=True, text=True, env=env
    )
    patch = patch_result.stdout

    # Reset to clean
    subprocess.run(["git", "checkout", "file.txt"], cwd=repo, capture_output=True, env=env)

    # Build bundle with patch
    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("git/branch.txt", b"main")
    builder.add_file("git/commit.txt", b"abc123")
    builder.add_file("git/uncommitted.patch", patch.encode())
    data = builder.build()
    reader = BundleReader(data)

    actions = apply_git_state(str(repo), reader, dry_run=False)
    assert any("Applied" in a or "patch" in a.lower() for a in actions)
    reader.close()


def test_capture_git_state_with_stash(tmp_path):
    """Git repo with stash entries."""
    env = {**os.environ, "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t"}
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=repo, capture_output=True)
    (repo / "f.txt").write_text("a\n")
    subprocess.run(["git", "add", "f.txt"], cwd=repo, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, env=env)
    (repo / "f.txt").write_text("b\n")
    subprocess.run(["git", "stash"], cwd=repo, capture_output=True, env=env)

    result = capture_git_state(str(repo))
    assert "git/stash.txt" in result


# --- tool_versions edge ---


def test_get_version_missing_command():
    result = _get_version(["nonexistent-binary-xyz"])
    assert result == ""


# --- bundle edge cases ---


def test_bundle_add_directory_tree(tmp_path):
    """add_directory_tree with nested files."""
    src = tmp_path / "src"
    (src / "a" / "b").mkdir(parents=True)
    (src / "f1.txt").write_text("f1")
    (src / "a" / "f2.txt").write_text("f2")
    (src / "a" / "b" / "f3.txt").write_text("f3")

    manifest = Manifest()
    builder = BundleBuilder(manifest)
    count = builder.add_directory_tree("tree", src)
    assert count == 3

    data = builder.build()
    reader = BundleReader(data)
    assert reader.read_file("tree/f1.txt") == b"f1"
    assert reader.read_file("tree/a/f2.txt") == b"f2"
    assert reader.read_file("tree/a/b/f3.txt") == b"f3"
    reader.close()


def test_bundle_add_directory_tree_nonexistent(tmp_path):
    builder = BundleBuilder(Manifest())
    count = builder.add_directory_tree("tree", tmp_path / "nonexistent")
    assert count == 0


def test_bundle_reader_extract_no_match(tmp_path):
    builder = BundleBuilder(Manifest())
    builder.add_file("session/test.txt", b"data")
    data = builder.build()
    reader = BundleReader(data)
    count = reader.extract_prefix("nonexistent", tmp_path / "out")
    assert count == 0
    reader.close()


def test_bundle_reader_read_json():
    builder = BundleBuilder(Manifest())
    builder.add_file("data.json", json.dumps({"key": "val"}).encode())
    data = builder.build()
    reader = BundleReader(data)
    assert reader.read_json("data.json") == {"key": "val"}
    reader.close()
