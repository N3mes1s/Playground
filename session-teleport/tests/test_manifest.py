"""Tests for manifest creation and serialization."""


from session_teleport.core.manifest import Manifest


def test_manifest_defaults():
    m = Manifest()
    assert m.version == "1.0"
    assert m.created_at  # auto-populated
    assert m.encrypted is False
    assert m.components == []


def test_manifest_to_json_roundtrip():
    m = Manifest(
        provider="claude_code",
        session_id="test-123",
        source_hostname="laptop",
        source_platform="darwin",
        source_cwd="/Users/me/project",
        components=["session", "git"],
    )
    j = m.to_json()
    m2 = Manifest.from_json(j)
    assert m2.provider == m.provider
    assert m2.session_id == m.session_id
    assert m2.source_hostname == m.source_hostname
    assert m2.components == ["session", "git"]


def test_manifest_from_dict():
    d = {
        "version": "1.0",
        "provider": "codex_cli",
        "session_id": "abc",
        "unknown_field": "ignored",
    }
    m = Manifest.from_dict(d)
    assert m.provider == "codex_cli"
    assert m.session_id == "abc"


def test_manifest_from_dict_missing_fields():
    m = Manifest.from_dict({"provider": "test"})
    assert m.provider == "test"
    assert m.session_id == ""  # default


def test_manifest_created_at_auto():
    m1 = Manifest()
    Manifest()
    assert m1.created_at  # not empty
    # Both should have timestamps (though potentially identical)
    assert "T" in m1.created_at  # ISO format


def test_manifest_preserves_explicit_created_at():
    m = Manifest(created_at="2025-01-01T00:00:00Z")
    assert m.created_at == "2025-01-01T00:00:00Z"
