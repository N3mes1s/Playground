"""Tests for path utilities."""

from session_teleport.utils.paths import (
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
    assert decoded == "/home/user/project"


def test_decode_cwd_no_leading_hyphen():
    decoded = decode_cwd("relative-path")
    assert decoded == "relative/path"


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
