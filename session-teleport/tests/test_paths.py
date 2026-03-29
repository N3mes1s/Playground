"""Tests for path utilities."""


from session_teleport.utils.paths import (
    _resolve_encoded_path,
    decode_cwd,
    encode_cwd,
    get_claude_dir,
    get_codex_dir,
    get_hostname,
    get_platform,
)


def test_encode_cwd_unix():
    assert encode_cwd("/home/user/project") == "-home-user-project"


def test_encode_cwd_root():
    assert encode_cwd("/") == "-"


def test_encode_cwd_nested():
    assert encode_cwd("/a/b/c/d") == "-a-b-c-d"


def test_decode_cwd_roundtrip():
    """decode(encode(p)) == p for simple paths without hyphens."""
    path = "/home/user/project"
    assert decode_cwd(encode_cwd(path)) == path


def test_decode_cwd_leading_hyphen():
    decoded = decode_cwd("-home-user-project")
    # Falls back to naive replacement since /home/user/project likely doesn't exist
    assert decoded.startswith("/")


def test_decode_cwd_no_leading_hyphen():
    decoded = decode_cwd("relative-path")
    assert decoded == "relative/path"


def test_decode_cwd_empty():
    assert decode_cwd("") == ""


def test_decode_cwd_filesystem_resolution(tmp_path):
    """When the path exists on disk, decode should use filesystem resolution."""
    # Create a directory with a hyphen: /tmp/xxx/my-project/src
    base = tmp_path / "my-project" / "src"
    base.mkdir(parents=True)

    # Encode it: the path parts are [tmp_path parts] + [my-project, src]
    full_path = str(base)
    encoded = encode_cwd(full_path)

    # Decode should resolve correctly via filesystem
    decoded = decode_cwd(encoded)
    assert decoded == full_path


def test_decode_cwd_fallback_when_no_match():
    """When filesystem resolution fails, fall back to naive replacement."""
    # Path that doesn't exist on disk
    decoded = decode_cwd("-nonexistent-fake-path-xyz")
    assert decoded == "/nonexistent/fake/path/xyz"


def test_resolve_encoded_path_empty():
    assert _resolve_encoded_path([]) is None


def test_resolve_encoded_path_root():
    """Should resolve simple existing paths."""
    # /tmp always exists
    result = _resolve_encoded_path(["tmp"])
    assert result == "/tmp"


def test_get_claude_dir():
    d = get_claude_dir()
    assert d.name == ".claude"
    assert d.parent.name  # has a parent (home dir)


def test_get_codex_dir():
    d = get_codex_dir()
    assert d.name == ".codex"


def test_get_hostname():
    h = get_hostname()
    assert isinstance(h, str)
    assert len(h) > 0


def test_get_platform():
    p = get_platform()
    assert p in ("linux", "darwin", "windows")
