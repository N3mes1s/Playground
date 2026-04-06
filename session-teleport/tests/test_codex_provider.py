"""Tests for Codex CLI provider."""

from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest
from session_teleport.providers.codex_cli import CodexCliProvider


def test_list_sessions(tmp_codex_dir):
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)

    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].session_id == session_uuid
    assert sessions[0].cwd == cwd
    assert sessions[0].provider == "codex_cli"
    assert sessions[0].extra is not None
    assert sessions[0].extra["rollout_file"].startswith("rollout-")
    assert sessions[0].extra["archived"] is False


def test_export_session(tmp_codex_dir):
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)

    manifest = Manifest(provider="codex_cli", session_id=session_uuid, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_uuid, builder)

    data = builder.build()
    reader = BundleReader(data)
    files = reader.list_files()

    # Should have the rollout file, config, and session index
    assert any("rollout-" in f for f in files)
    assert any("config.toml" in f for f in files)
    assert any("session_index.jsonl" in f for f in files)
    reader.close()


def test_export_import_roundtrip(tmp_codex_dir, tmp_path):
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)

    manifest = Manifest(provider="codex_cli", session_id=session_uuid, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_uuid, builder)
    data = builder.build()

    # Import into a different codex dir
    target_codex = tmp_path / "target_codex"
    target_provider = CodexCliProvider(base_dir=target_codex)

    reader = BundleReader(data)
    target_provider.import_session(reader)

    # Verify imported sessions
    imported = target_provider.list_sessions()
    assert len(imported) == 1
    assert imported[0].session_id == session_uuid
    reader.close()


def test_import_with_cwd_rewrite(tmp_codex_dir, tmp_path):
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)

    manifest = Manifest(provider="codex_cli", session_id=session_uuid, source_cwd=cwd)
    builder = BundleBuilder(manifest)
    provider.export_session(session_uuid, builder)
    data = builder.build()

    # Import with different target dir
    target_codex = tmp_path / "target_codex"
    target_provider = CodexCliProvider(base_dir=target_codex)
    new_cwd = "/home/otheruser/project"

    reader = BundleReader(data)
    reader.manifest.source_cwd = cwd  # Set source for rewrite
    target_provider.import_session(reader, target_dir=new_cwd)

    # Verify the imported session has rewritten cwd
    imported = target_provider.list_sessions()
    assert len(imported) == 1
    assert imported[0].cwd == new_cwd
    reader.close()


def test_find_rollout_by_prefix(tmp_codex_dir):
    codex_dir, session_uuid, cwd = tmp_codex_dir
    provider = CodexCliProvider(base_dir=codex_dir)

    # Should find by prefix
    path = provider._find_rollout_by_id(session_uuid[:8])
    assert path is not None
    assert "rollout-" in path.name

    # Should not find garbage
    path = provider._find_rollout_by_id("nonexistent-id")
    assert path is None


def test_date_partitioned_sessions(tmp_path):
    """Test that sessions in YYYY/MM/DD/ subdirectories are discovered."""
    import json
    codex_dir = tmp_path / ".codex"
    nested_dir = codex_dir / "sessions" / "2025" / "05" / "07"
    nested_dir.mkdir(parents=True)

    session_uuid = "aaaa1111-2222-3333-4444-555566667777"
    rollout_name = f"rollout-2025-05-07T17-24-21-{session_uuid}.jsonl"

    meta = {
        "meta": {
            "id": session_uuid,
            "timestamp": "2025-05-07T17:24:21Z",
            "source": "cli",
            "cwd": "/home/user/project",
        },
    }
    (nested_dir / rollout_name).write_text(json.dumps(meta) + "\n")

    provider = CodexCliProvider(base_dir=codex_dir)
    sessions = provider.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].session_id == session_uuid
    assert sessions[0].cwd == "/home/user/project"
