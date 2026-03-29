"""Tests for bundle creation and extraction."""

import pytest

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


def test_bundle_reader_context_manager():
    builder = BundleBuilder(Manifest())
    builder.add_file("test.txt", b"data")
    data = builder.build()

    with BundleReader(data) as reader:
        assert reader.read_file("test.txt") == b"data"


def test_bundle_reader_read_missing():
    builder = BundleBuilder(Manifest())
    builder.add_file("exists.txt", b"data")
    data = builder.build()
    reader = BundleReader(data)
    with pytest.raises(FileNotFoundError):
        reader.read_file("missing.txt")
    reader.close()


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
