"""Shared test helper functions for session-teleport tests."""

from __future__ import annotations

import json

from session_teleport.core.bundle import BundleBuilder
from session_teleport.core.manifest import Manifest
from session_teleport.utils.paths import encode_cwd


def make_claude_bundle(
    session_id: str = "test-session-123",
    cwd: str = "/home/user/project",
    messages: list[dict] | None = None,
    subagents: dict[str, dict] | None = None,
    include_git: bool = False,
) -> bytes:
    """Build a minimal Claude Code bundle for testing."""
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

    encoded = encode_cwd(cwd)
    jsonl = "\n".join(json.dumps(m) for m in messages) + "\n"
    builder.add_file(f"session/projects/{encoded}/{session_id}.jsonl", jsonl.encode())

    meta = {"pid": 12345, "sessionId": session_id, "cwd": cwd}
    builder.add_file("session/sessions/0.json", json.dumps(meta).encode())

    if subagents:
        for agent_id, agent_data in subagents.items():
            if "meta" in agent_data:
                builder.add_file(
                    f"session/projects/{encoded}/{session_id}"
                    f"/subagents/{agent_id}.meta.json",
                    json.dumps(agent_data["meta"]).encode(),
                )
            if "messages" in agent_data:
                agent_jsonl = (
                    "\n".join(json.dumps(m) for m in agent_data["messages"]) + "\n"
                )
                builder.add_file(
                    f"session/projects/{encoded}/{session_id}"
                    f"/subagents/{agent_id}.jsonl",
                    agent_jsonl.encode(),
                )

    if include_git:
        builder.add_file("git/branch.txt", b"main")
        builder.add_file("git/commit.txt", b"abc123")
        builder.add_file("git/remote.txt", b"https://github.com/test/repo.git")

    return builder.build()


def make_codex_bundle(
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
            {
                "type": "user_message",
                "content": "Hello",
                "timestamp": "2024-01-01T00:00:00Z",
            },
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
