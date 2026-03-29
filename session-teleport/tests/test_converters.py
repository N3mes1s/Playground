"""Tests for cross-provider session converters."""

import json

import pytest

from session_teleport.converters import get_converter
from session_teleport.converters.base import (
    flatten_content,
    parse_claude_jsonl,
    parse_codex_jsonl,
)
from session_teleport.converters.claude_to_codex import ClaudeToCodexConverter
from session_teleport.converters.codex_to_claude import CodexToClaudeConverter
from session_teleport.core.bundle import BundleBuilder, BundleReader
from session_teleport.core.manifest import Manifest

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_claude_bundle(
    session_id: str = "test-session-123",
    cwd: str = "/home/user/project",
    messages: list[dict] | None = None,
    subagents: dict[str, dict] | None = None,
    include_git: bool = False,
) -> bytes:
    """Build a minimal Claude Code bundle for testing."""
    from session_teleport.utils.paths import encode_cwd

    manifest = Manifest(
        provider="claude_code",
        session_id=session_id,
        source_hostname="test-host",
        source_platform="linux",
        source_cwd=cwd,
        components=["session"] + (["git"] if include_git else []),
    )
    builder = BundleBuilder(manifest)

    if messages is None:
        messages = [
            {
                "type": "user",
                "message": {"role": "user", "content": "Hello"},
                "uuid": "uuid-1",
                "parentUuid": None,
                "timestamp": "2024-01-01T00:00:00Z",
                "sessionId": session_id,
                "cwd": cwd,
            },
            {
                "type": "assistant",
                "message": {"role": "assistant", "content": "Hi there!"},
                "uuid": "uuid-2",
                "parentUuid": "uuid-1",
                "timestamp": "2024-01-01T00:00:01Z",
                "sessionId": session_id,
                "cwd": cwd,
            },
        ]

    encoded_cwd = encode_cwd(cwd)
    jsonl = "\n".join(json.dumps(m) for m in messages) + "\n"
    builder.add_file(f"session/projects/{encoded_cwd}/{session_id}.jsonl", jsonl.encode())

    # Session metadata
    meta = {"pid": 12345, "sessionId": session_id, "cwd": cwd}
    builder.add_file("session/sessions/0.json", json.dumps(meta).encode())

    # Subagents
    if subagents:
        for agent_id, agent_data in subagents.items():
            if "meta" in agent_data:
                builder.add_file(
                    f"session/projects/{encoded_cwd}/{session_id}/subagents/{agent_id}.meta.json",
                    json.dumps(agent_data["meta"]).encode(),
                )
            if "messages" in agent_data:
                agent_jsonl = "\n".join(json.dumps(m) for m in agent_data["messages"]) + "\n"
                builder.add_file(
                    f"session/projects/{encoded_cwd}/{session_id}/subagents/{agent_id}.jsonl",
                    agent_jsonl.encode(),
                )

    # Git files
    if include_git:
        builder.add_file("git/branch.txt", b"main")
        builder.add_file("git/commit.txt", b"abc123")
        builder.add_file("git/remote.txt", b"https://github.com/test/repo.git")

    return builder.build()


def _make_codex_bundle(
    session_id: str = "codex-session-456",
    cwd: str = "/home/user/project",
    messages: list[dict] | None = None,
    include_git: bool = False,
) -> bytes:
    """Build a minimal Codex CLI bundle for testing."""
    manifest = Manifest(
        provider="codex_cli",
        session_id=session_id,
        source_hostname="test-host",
        source_platform="linux",
        source_cwd=cwd,
        components=["session"] + (["git"] if include_git else []),
    )
    builder = BundleBuilder(manifest)

    meta_line = {
        "meta": {
            "id": session_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "cwd": cwd,
            "source": "codex",
        },
        "git": {},
    }
    if messages is None:
        messages = [
            {"type": "user_message", "content": "Hello", "timestamp": "2024-01-01T00:00:00Z"},
            {
                "type": "assistant_message",
                "content": "Hi there!",
                "timestamp": "2024-01-01T00:00:01Z",
            },
        ]

    rollout_lines = [meta_line, *messages]
    rollout_data = "\n".join(json.dumps(line) for line in rollout_lines) + "\n"
    rollout_name = f"rollout-2024-01-01T00-00-00-{session_id}.jsonl"
    builder.add_file(f"session/sessions/{rollout_name}", rollout_data.encode())

    if include_git:
        builder.add_file("git/branch.txt", b"main")
        builder.add_file("git/commit.txt", b"abc123")

    return builder.build()


# ── flatten_content tests ────────────────────────────────────────────────


def test_flatten_content_string():
    assert flatten_content("hello world") == "hello world"


def test_flatten_content_text_blocks():
    content = [
        {"type": "text", "text": "First paragraph."},
        {"type": "text", "text": "Second paragraph."},
    ]
    result = flatten_content(content)
    assert "First paragraph." in result
    assert "Second paragraph." in result


def test_flatten_content_tool_use():
    content = [
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/tmp/test.py"}},
    ]
    result = flatten_content(content)
    assert "[Tool: Read]" in result
    assert "/tmp/test.py" in result


def test_flatten_content_tool_result():
    content = [
        {"type": "tool_result", "content": "file contents here"},
    ]
    result = flatten_content(content)
    assert "[Result]" in result
    assert "file contents here" in result


def test_flatten_content_tool_result_nested_list():
    content = [
        {
            "type": "tool_result",
            "content": [
                {"type": "text", "text": "line 1"},
                {"type": "text", "text": "line 2"},
            ],
        },
    ]
    result = flatten_content(content)
    assert "line 1" in result
    assert "line 2" in result


def test_flatten_content_thinking_stripped():
    content = [
        {"type": "thinking", "text": "internal reasoning"},
        {"type": "text", "text": "visible response"},
    ]
    result = flatten_content(content)
    assert "internal reasoning" not in result
    assert "visible response" in result


def test_flatten_content_mixed():
    content = [
        {"type": "text", "text": "Let me read the file."},
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/tmp/a.py"}},
        {"type": "tool_result", "content": "def foo(): pass"},
        {"type": "text", "text": "Here's the function."},
    ]
    result = flatten_content(content)
    assert "Let me read the file." in result
    assert "[Tool: Read]" in result
    assert "[Result]" in result
    assert "Here's the function." in result


def test_flatten_content_non_dict_block():
    content = ["plain string in list"]
    result = flatten_content(content)
    assert "plain string in list" in result


def test_flatten_content_unknown_block_type():
    content = [{"type": "image", "text": "some image data"}]
    result = flatten_content(content)
    assert "some image data" in result


def test_flatten_content_non_list_non_string():
    assert flatten_content(42) == "42"


def test_flatten_content_empty_tool_result():
    content = [{"type": "tool_result", "content": ""}]
    result = flatten_content(content)
    assert result == ""


def test_flatten_content_tool_use_command():
    content = [
        {"type": "tool_use", "name": "Bash", "input": {"command": "ls -la"}},
    ]
    result = flatten_content(content)
    assert "ls -la" in result


def test_flatten_content_tool_use_pattern():
    content = [
        {"type": "tool_use", "name": "Grep", "input": {"pattern": "TODO"}},
    ]
    result = flatten_content(content)
    assert "pattern=TODO" in result


def test_flatten_content_tool_use_prompt():
    content = [
        {"type": "tool_use", "name": "Agent", "input": {"prompt": "Find all tests"}},
    ]
    result = flatten_content(content)
    assert "Find all tests" in result


def test_flatten_content_tool_use_empty_input():
    content = [{"type": "tool_use", "name": "Unknown", "input": {}}]
    result = flatten_content(content)
    assert "[Tool: Unknown]" in result


def test_flatten_content_tool_use_fallback_input():
    content = [
        {"type": "tool_use", "name": "Custom", "input": {"some_key": "some_value"}},
    ]
    result = flatten_content(content)
    assert "some_value" in result


def test_flatten_content_tool_result_string_in_list():
    content = [
        {"type": "tool_result", "content": ["raw string item"]},
    ]
    result = flatten_content(content)
    assert "raw string item" in result


# ── parse_claude_jsonl tests ────────────────────────────────────────────


def test_parse_claude_jsonl_basic():
    lines = [
        {"type": "user", "message": {"role": "user", "content": "hi"}, "uuid": "1"},
        {"type": "assistant", "message": {"role": "assistant", "content": "hello"}, "uuid": "2"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    result = parse_claude_jsonl(data)
    assert len(result) == 2
    assert result[0]["message"]["role"] == "user"
    assert result[1]["message"]["role"] == "assistant"


def test_parse_claude_jsonl_skips_compact_metadata():
    lines = [
        {"compactMetadata": True, "data": "compact stuff"},
        {"type": "user", "message": {"role": "user", "content": "hi"}, "uuid": "1"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    result = parse_claude_jsonl(data)
    assert len(result) == 1


def test_parse_claude_jsonl_skips_sidechain():
    lines = [
        {"type": "user", "message": {"role": "user", "content": "hi"}, "uuid": "1"},
        {
            "type": "assistant",
            "message": {"role": "assistant", "content": "sub"},
            "uuid": "2",
            "isSidechain": True,
        },
        {"type": "assistant", "message": {"role": "assistant", "content": "main"}, "uuid": "3"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    result = parse_claude_jsonl(data)
    assert len(result) == 2
    assert result[1]["message"]["content"] == "main"


def test_parse_claude_jsonl_skips_meta_and_summary():
    lines = [
        {"isMeta": True, "data": "meta stuff"},
        {"isCompactSummary": True, "data": "summary"},
        {"type": "user", "message": {"role": "user", "content": "hi"}, "uuid": "1"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    result = parse_claude_jsonl(data)
    assert len(result) == 1


def test_parse_claude_jsonl_handles_bad_json():
    data = b'{"type":"user","message":{"role":"user","content":"hi"},"uuid":"1"}\nnot json\n'
    result = parse_claude_jsonl(data)
    assert len(result) == 1


def test_parse_claude_jsonl_skips_no_message():
    lines = [
        {"type": "summary", "data": "no message field"},
        {"type": "user", "message": {"role": "user", "content": "hi"}, "uuid": "1"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    result = parse_claude_jsonl(data)
    assert len(result) == 1


# ── parse_codex_jsonl tests ─────────────────────────────────────────────


def test_parse_codex_jsonl_basic():
    lines = [
        {"meta": {"id": "s1", "timestamp": "2024-01-01T00:00:00Z", "cwd": "/tmp"}},
        {"type": "user_message", "content": "hi"},
        {"type": "assistant_message", "content": "hello"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    meta, messages = parse_codex_jsonl(data)
    assert meta is not None
    assert meta["meta"]["id"] == "s1"
    assert len(messages) == 2


def test_parse_codex_jsonl_no_meta():
    lines = [
        {"type": "user_message", "content": "hi"},
    ]
    data = "\n".join(json.dumps(ln) for ln in lines).encode()
    meta, messages = parse_codex_jsonl(data)
    assert meta is None
    assert len(messages) == 1


def test_parse_codex_jsonl_handles_bad_json():
    data = b'{"meta":{"id":"s1"}}\nnot json\n{"type":"user_message","content":"hi"}\n'
    meta, messages = parse_codex_jsonl(data)
    assert meta is not None
    assert len(messages) == 1


# ── get_converter registry tests ────────────────────────────────────────


def test_get_converter_claude_to_codex():
    converter = get_converter("claude_code", "codex_cli")
    assert converter is not None
    assert isinstance(converter, ClaudeToCodexConverter)


def test_get_converter_codex_to_claude():
    converter = get_converter("codex_cli", "claude_code")
    assert converter is not None
    assert isinstance(converter, CodexToClaudeConverter)


def test_get_converter_unknown_pair():
    assert get_converter("unknown", "claude_code") is None
    assert get_converter("claude_code", "unknown") is None


def test_get_converter_same_provider():
    assert get_converter("claude_code", "claude_code") is None


# ── Claude → Codex conversion tests ─────────────────────────────────────


def test_claude_to_codex_basic():
    bundle_data = _make_claude_bundle()
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader)

    assert result.manifest.provider == "codex_cli"
    assert result.manifest.converted_from == "claude_code"

    # Find the rollout file
    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    assert len(rollout_files) == 1

    rollout_data = result.read_file(rollout_files[0]).decode()
    lines = [json.loads(ln) for ln in rollout_data.strip().split("\n")]

    # First line should be meta
    assert "meta" in lines[0]
    assert lines[0]["meta"]["source"] == "converted-from-claude"

    # Should have user and assistant messages
    msg_types = [ln.get("type") for ln in lines[1:]]
    assert "user_message" in msg_types
    assert "assistant_message" in msg_types

    result.close()


def test_claude_to_codex_preserves_content():
    bundle_data = _make_claude_bundle()
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader)

    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    rollout_data = result.read_file(rollout_files[0]).decode()
    lines = [json.loads(ln) for ln in rollout_data.strip().split("\n")]

    contents = [ln.get("content", "") for ln in lines[1:]]
    assert "Hello" in contents
    assert "Hi there!" in contents

    result.close()


def test_claude_to_codex_with_git():
    bundle_data = _make_claude_bundle(include_git=True)
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader)

    # Git info should be in meta line
    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    rollout_data = result.read_file(rollout_files[0]).decode()
    meta_line = json.loads(rollout_data.split("\n")[0])

    assert meta_line["git"]["branch"] == "main"
    assert meta_line["git"]["commit_hash"] == "abc123"
    assert meta_line["git"]["origin_url"] == "https://github.com/test/repo.git"

    # Git files should be copied
    all_files = result.list_files()
    assert any(f.startswith("git/") for f in all_files)

    result.close()


def test_claude_to_codex_with_subagents():
    subagent_id = "agent-abc"
    subagents = {
        subagent_id: {
            "meta": {"agentType": "Explore", "description": "Search codebase"},
            "messages": [
                {
                    "type": "user",
                    "message": {"role": "user", "content": "Find tests"},
                    "uuid": "sub-1",
                },
                {
                    "type": "assistant",
                    "message": {"role": "assistant", "content": "Found 5 test files"},
                    "uuid": "sub-2",
                },
            ],
        }
    }

    # Create message that references the Agent tool
    messages = [
        {
            "type": "user",
            "message": {"role": "user", "content": "Search the codebase"},
            "uuid": "uuid-1",
            "parentUuid": None,
            "timestamp": "2024-01-01T00:00:00Z",
            "sessionId": "test-session-123",
            "cwd": "/home/user/project",
        },
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Let me search."},
                    {"type": "tool_use", "name": "Agent", "input": {"prompt": "Find tests"}},
                ],
            },
            "uuid": "uuid-2",
            "parentUuid": "uuid-1",
            "timestamp": "2024-01-01T00:00:01Z",
            "sessionId": "test-session-123",
            "cwd": "/home/user/project",
        },
    ]

    bundle_data = _make_claude_bundle(messages=messages, subagents=subagents)
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader)

    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    rollout_data = result.read_file(rollout_files[0]).decode()
    lines = [json.loads(ln) for ln in rollout_data.strip().split("\n")]

    # Check that messages exist (subagent inlining depends on toolUseResult matching)
    all_content = " ".join(ln.get("content", "") for ln in lines[1:])
    assert "Search the codebase" in all_content or "Let me search" in all_content

    result.close()


def test_claude_to_codex_with_tool_use_content():
    """Verify tool_use blocks in content are flattened."""
    messages = [
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Reading file..."},
                    {"type": "tool_use", "name": "Read", "input": {"file_path": "/tmp/x.py"}},
                ],
            },
            "uuid": "uuid-1",
            "parentUuid": None,
            "timestamp": "2024-01-01T00:00:00Z",
            "sessionId": "test-session-123",
            "cwd": "/home/user/project",
        },
    ]
    bundle_data = _make_claude_bundle(messages=messages)
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader)

    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    rollout_data = result.read_file(rollout_files[0]).decode()
    lines = [json.loads(ln) for ln in rollout_data.strip().split("\n")]

    assistant_msgs = [ln for ln in lines[1:] if ln.get("type") == "assistant_message"]
    assert len(assistant_msgs) >= 1
    assert "[Tool: Read]" in assistant_msgs[0]["content"]

    result.close()


def test_claude_to_codex_no_jsonl_raises():
    """Conversion should fail if no conversation log exists."""
    manifest = Manifest(
        provider="claude_code",
        session_id="missing-session",
        source_hostname="test-host",
        source_platform="linux",
        source_cwd="/tmp",
        components=["session"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/0.json", b'{"pid": 1}')
    data = builder.build()
    reader = BundleReader(data)

    converter = ClaudeToCodexConverter()
    with pytest.raises(ValueError, match="No conversation log found"):
        converter.convert(reader)


def test_claude_to_codex_target_cwd():
    """target_cwd should override the source CWD."""
    bundle_data = _make_claude_bundle()
    reader = BundleReader(bundle_data)

    converter = ClaudeToCodexConverter()
    result = converter.convert(reader, target_cwd="/new/path")

    assert result.manifest.source_cwd == "/new/path"

    rollout_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    rollout_data = result.read_file(rollout_files[0]).decode()
    meta_line = json.loads(rollout_data.split("\n")[0])
    assert meta_line["meta"]["cwd"] == "/new/path"

    result.close()


# ── Codex → Claude conversion tests ─────────────────────────────────────


def test_codex_to_claude_basic():
    bundle_data = _make_codex_bundle()
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    assert result.manifest.provider == "claude_code"
    assert result.manifest.converted_from == "codex_cli"

    # Should have a session metadata file
    meta_file = result.read_json("session/sessions/0.json")
    assert meta_file["kind"] == "imported"
    assert meta_file["pid"] == 0

    # Should have a JSONL conversation log
    jsonl_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    assert len(jsonl_files) == 1

    jsonl_data = result.read_file(jsonl_files[0]).decode()
    lines = [json.loads(ln) for ln in jsonl_data.strip().split("\n")]
    assert len(lines) == 2

    result.close()


def test_codex_to_claude_preserves_content():
    bundle_data = _make_codex_bundle()
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    jsonl_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    jsonl_data = result.read_file(jsonl_files[0]).decode()
    lines = [json.loads(ln) for ln in jsonl_data.strip().split("\n")]

    assert lines[0]["message"]["content"] == "Hello"
    assert lines[0]["message"]["role"] == "user"
    assert lines[1]["message"]["content"] == "Hi there!"
    assert lines[1]["message"]["role"] == "assistant"

    result.close()


def test_codex_to_claude_uuid_chain():
    """Verify parentUuid chain is correctly built."""
    messages = [
        {"type": "user_message", "content": "First", "timestamp": ""},
        {"type": "assistant_message", "content": "Second", "timestamp": ""},
        {"type": "user_message", "content": "Third", "timestamp": ""},
    ]
    bundle_data = _make_codex_bundle(messages=messages)
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    jsonl_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    jsonl_data = result.read_file(jsonl_files[0]).decode()
    lines = [json.loads(ln) for ln in jsonl_data.strip().split("\n")]

    assert len(lines) == 3
    # First message has no parent
    assert lines[0]["parentUuid"] is None
    # Second message's parent is first
    assert lines[1]["parentUuid"] == lines[0]["uuid"]
    # Third message's parent is second
    assert lines[2]["parentUuid"] == lines[1]["uuid"]
    # All UUIDs are unique
    uuids = [ln["uuid"] for ln in lines]
    assert len(set(uuids)) == 3

    result.close()


def test_codex_to_claude_deterministic_uuids():
    """UUIDs should be deterministic for the same session."""
    bundle_data = _make_codex_bundle()

    reader1 = BundleReader(bundle_data)
    result1 = converter_result(reader1)

    reader2 = BundleReader(bundle_data)
    result2 = converter_result(reader2)

    assert result1 == result2


def converter_result(reader):
    converter = CodexToClaudeConverter()
    result = converter.convert(reader)
    jsonl_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    data = result.read_file(jsonl_files[0]).decode()
    result.close()
    return data


def test_codex_to_claude_no_rollout_raises():
    """Conversion should fail if no rollout file exists."""
    manifest = Manifest(
        provider="codex_cli",
        session_id="missing-session",
        source_hostname="test-host",
        source_platform="linux",
        source_cwd="/tmp",
        components=["session"],
    )
    builder = BundleBuilder(manifest)
    builder.add_file("session/sessions/meta.json", b'{"data": "no rollout"}')
    data = builder.build()
    reader = BundleReader(data)

    converter = CodexToClaudeConverter()
    with pytest.raises(ValueError, match="No rollout file found"):
        converter.convert(reader)


def test_codex_to_claude_target_cwd():
    bundle_data = _make_codex_bundle()
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader, target_cwd="/override/path")

    assert result.manifest.source_cwd == "/override/path"
    meta = result.read_json("session/sessions/0.json")
    assert meta["cwd"] == "/override/path"

    result.close()


def test_codex_to_claude_skips_empty_content():
    """Messages with empty content should be skipped."""
    messages = [
        {"type": "user_message", "content": "Hello", "timestamp": ""},
        {"type": "assistant_message", "content": "", "timestamp": ""},
        {"type": "user_message", "content": "Goodbye", "timestamp": ""},
    ]
    bundle_data = _make_codex_bundle(messages=messages)
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    jsonl_files = [f for f in result.list_files() if f.endswith(".jsonl")]
    jsonl_data = result.read_file(jsonl_files[0]).decode()
    lines = [json.loads(ln) for ln in jsonl_data.strip().split("\n")]

    assert len(lines) == 2
    assert lines[0]["message"]["content"] == "Hello"
    assert lines[1]["message"]["content"] == "Goodbye"

    result.close()


def test_codex_to_claude_copies_git_env():
    """Git and env files should be copied through."""
    manifest = Manifest(
        provider="codex_cli",
        session_id="codex-123",
        source_hostname="test-host",
        source_platform="linux",
        source_cwd="/tmp",
        components=["session", "git", "env"],
    )
    builder = BundleBuilder(manifest)
    meta_line = {"meta": {"id": "codex-123", "timestamp": "2024-01-01T00:00:00Z", "cwd": "/tmp"}}
    msg = {"type": "user_message", "content": "hi", "timestamp": ""}
    rollout = json.dumps(meta_line) + "\n" + json.dumps(msg) + "\n"
    builder.add_file("session/sessions/rollout.jsonl", rollout.encode())
    builder.add_file("git/branch.txt", b"develop")
    builder.add_file("env/tool_versions.json", b'{"node": "18.0"}')
    data = builder.build()

    reader = BundleReader(data)
    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    assert result.read_file("git/branch.txt") == b"develop"
    assert result.read_file("env/tool_versions.json") == b'{"node": "18.0"}'

    result.close()


def test_codex_to_claude_timestamp_parsing():
    """Should parse ISO timestamps from meta line."""
    messages = [
        {"type": "user_message", "content": "hi", "timestamp": "2024-06-15T10:30:00Z"},
    ]
    bundle_data = _make_codex_bundle(messages=messages)
    reader = BundleReader(bundle_data)

    converter = CodexToClaudeConverter()
    result = converter.convert(reader)

    meta = result.read_json("session/sessions/0.json")
    assert meta["startedAt"] > 0

    result.close()


# ── Roundtrip tests ──────────────────────────────────────────────────────


def test_roundtrip_claude_codex_claude():
    """Claude→Codex→Claude should preserve message text."""
    original_messages = [
        {
            "type": "user",
            "message": {"role": "user", "content": "What is 2+2?"},
            "uuid": "u1",
            "parentUuid": None,
            "timestamp": "2024-01-01T00:00:00Z",
            "sessionId": "roundtrip-test",
            "cwd": "/tmp",
        },
        {
            "type": "assistant",
            "message": {"role": "assistant", "content": "The answer is 4."},
            "uuid": "u2",
            "parentUuid": "u1",
            "timestamp": "2024-01-01T00:00:01Z",
            "sessionId": "roundtrip-test",
            "cwd": "/tmp",
        },
    ]

    # Claude → Codex
    bundle1 = _make_claude_bundle(
        session_id="roundtrip-test", cwd="/tmp", messages=original_messages
    )
    reader1 = BundleReader(bundle1)
    codex_result = ClaudeToCodexConverter().convert(reader1)

    # Codex → Claude
    claude_result = CodexToClaudeConverter().convert(codex_result)

    # Check content preserved
    jsonl_files = [f for f in claude_result.list_files() if f.endswith(".jsonl")]
    jsonl_data = claude_result.read_file(jsonl_files[0]).decode()
    lines = [json.loads(ln) for ln in jsonl_data.strip().split("\n")]

    contents = [ln["message"]["content"] for ln in lines]
    assert "What is 2+2?" in contents
    assert "The answer is 4." in contents

    claude_result.close()


def test_roundtrip_codex_claude_codex():
    """Codex→Claude→Codex should preserve message text."""
    messages = [
        {
            "type": "user_message",
            "content": "Explain recursion",
            "timestamp": "2024-01-01T00:00:00Z",
        },
        {
            "type": "assistant_message",
            "content": "Recursion is when a function calls itself.",
            "timestamp": "2024-01-01T00:00:01Z",
        },
    ]

    # Codex → Claude
    bundle1 = _make_codex_bundle(messages=messages)
    reader1 = BundleReader(bundle1)
    claude_result = CodexToClaudeConverter().convert(reader1)

    # Claude → Codex
    codex_result = ClaudeToCodexConverter().convert(claude_result)

    rollout_files = [f for f in codex_result.list_files() if f.endswith(".jsonl")]
    rollout_data = codex_result.read_file(rollout_files[0]).decode()
    lines = [json.loads(ln) for ln in rollout_data.strip().split("\n")]

    contents = [ln.get("content", "") for ln in lines[1:]]
    assert "Explain recursion" in contents
    assert "Recursion is when a function calls itself." in contents

    codex_result.close()


# ── CLI integration tests ────────────────────────────────────────────────


def test_cli_import_target_provider_flag(tmp_path):
    """Test that --target-provider triggers conversion during import."""
    from click.testing import CliRunner

    from session_teleport.cli import main
    from session_teleport.transfer.file_transfer import save_bundle

    bundle_data = _make_claude_bundle()
    bundle_path = tmp_path / "test.stp"
    save_bundle(bundle_data, bundle_path)

    runner = CliRunner()
    result = runner.invoke(main, [
        "import", str(bundle_path),
        "--target-provider", "codex",
        "--dry-run",
        "--no-apply-git",
    ])

    assert result.exit_code == 0
    assert "codex_cli" in result.output or "Dry run" in result.output


def test_cli_import_no_converter_available(tmp_path):
    """Test error when no converter exists for the pair."""
    from unittest.mock import patch

    from click.testing import CliRunner

    from session_teleport.cli import main
    from session_teleport.transfer.file_transfer import save_bundle

    bundle_data = _make_claude_bundle()
    bundle_path = tmp_path / "test.stp"
    save_bundle(bundle_data, bundle_path)

    runner = CliRunner()
    with patch("session_teleport.converters.get_converter", return_value=None):
        result = runner.invoke(main, [
            "import", str(bundle_path),
            "--target-provider", "codex",
            "--dry-run",
        ])

    assert result.exit_code == 1
    assert "No converter available" in result.output


def test_cli_import_same_provider_no_conversion(tmp_path):
    """Specifying same provider as bundle should skip conversion."""
    from click.testing import CliRunner

    from session_teleport.cli import main
    from session_teleport.transfer.file_transfer import save_bundle

    bundle_data = _make_claude_bundle()
    bundle_path = tmp_path / "test.stp"
    save_bundle(bundle_data, bundle_path)

    runner = CliRunner()
    result = runner.invoke(main, [
        "import", str(bundle_path),
        "--target-provider", "claude",
        "--dry-run",
        "--no-apply-git",
    ])

    # Should succeed without conversion (claude_code == claude)
    assert result.exit_code == 0
