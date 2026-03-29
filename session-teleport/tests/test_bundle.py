"""Tests for bundle creation and extraction."""

from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest


def test_bundle_roundtrip():
    manifest = Manifest(
        provider="claude_code",
        session_id="test-123",
        source_hostname="machine-a",
        source_platform="linux",
        source_cwd="/home/user/project",
        components=["session"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/test.txt", b"hello world")
    builder.add_file("session/nested/deep.json", b'{"key": "value"}')

    data = builder.build()

    reader = BundleReader(data)
    assert reader.manifest.provider == "claude_code"
    assert reader.manifest.session_id == "test-123"
    assert reader.read_file("session/test.txt") == b"hello world"
    assert reader.read_json("session/nested/deep.json") == {"key": "value"}

    files = reader.list_files()
    assert "manifest.json" in files
    assert "session/test.txt" in files
    reader.close()


def test_bundle_encrypted_roundtrip():
    manifest = Manifest(provider="claude_code", session_id="enc-test")
    builder = BundleBuilder(manifest)
    builder.add_file("session/secret.txt", b"classified data")

    data = builder.build(passphrase="my-secret-pass")

    # Should fail without passphrase (not valid gzip)
    assert data[:2] != b"\x1f\x8b"

    reader = BundleReader(data, passphrase="my-secret-pass")
    assert reader.read_file("session/secret.txt") == b"classified data"
    assert reader.manifest.encrypted is True
    reader.close()


def test_bundle_extract_prefix(tmp_path):
    manifest = Manifest(provider="test", session_id="x")
    builder = BundleBuilder(manifest)
    builder.add_file("session/a.txt", b"aaa")
    builder.add_file("session/sub/b.txt", b"bbb")
    builder.add_file("git/branch.txt", b"main")

    data = builder.build()
    reader = BundleReader(data)

    count = reader.extract_prefix("session", tmp_path / "out")
    assert count == 2
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"aaa"
    assert (tmp_path / "out" / "sub" / "b.txt").read_bytes() == b"bbb"
    reader.close()
