"""
Parse agent session data into a normalized conversation model.

Supports:
- Claude Code JSONL session logs (real format with streaming chunks)
- Generic agent JSON format (for any agent framework)

Key insight about Claude Code JSONL format:
- Each tool call generates a user→assistant round-trip (tool_result → response)
- Real user messages have text content, tool approvals have tool_result content
- We merge consecutive tool call round-trips into one logical assistant turn
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolCall:
    """A single tool invocation within a turn."""
    name: str
    input_tokens: int = 0
    output_tokens: int = 0
    duration_ms: int = 0
    children: list["ToolCall"] = field(default_factory=list)
    input_preview: str = ""
    output_preview: str = ""


@dataclass
class Turn:
    """One logical turn (all assistant work between real user messages)."""
    index: int
    role: str
    thinking_tokens: int = 0
    output_tokens: int = 0
    input_tokens: int = 0
    tool_calls: list[ToolCall] = field(default_factory=list)
    text_preview: str = ""
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # Number of API calls merged into this turn
    api_calls: int = 0
    # Duration from result events (teleport export)
    duration_ms: int = 0
    duration_api_ms: int = 0


@dataclass
class Session:
    """A full agent session."""
    turns: list[Turn] = field(default_factory=list)
    model: str = ""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    session_id: str = ""

    def compute_totals(self):
        self.total_input_tokens = sum(t.input_tokens for t in self.turns)
        self.total_output_tokens = sum(t.output_tokens for t in self.turns)


def _is_real_user_message(rec: dict) -> bool:
    """Distinguish real user input from tool_result responses."""
    if rec.get("type") != "user":
        return False
    msg = rec.get("message", {})
    content = msg.get("content", "")
    if isinstance(content, str) and content.strip():
        return True
    if isinstance(content, list):
        # tool_result blocks are not real user input
        has_text = any(
            isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip()
            for b in content
        )
        has_only_tool_results = all(
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in content
        )
        if has_only_tool_results:
            return False
        return has_text
    return False


def parse_claude_code_jsonl(path: str) -> Session:
    """Parse Claude Code's JSONL session log.

    Merges all assistant API calls between real user messages into one logical
    Turn. This means a turn that calls 10 tools shows up as one turn with 10
    tool calls, not 10 separate turns.
    """
    lines = Path(path).read_text().strip().split("\n")
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    session = Session()
    turn_idx = 0
    current_turn = None

    for rec in records:
        rec_type = rec.get("type", "")
        if rec_type not in ("user", "assistant"):
            continue

        msg = rec.get("message", {})
        if not isinstance(msg, dict):
            continue

        if not session.model:
            session.model = msg.get("model", "")
        if not session.session_id:
            session.session_id = rec.get("sessionId", "")

        # Real user message = new logical turn boundary
        if _is_real_user_message(rec):
            if current_turn is not None:
                session.turns.append(current_turn)
                turn_idx += 1

            # Add user turn
            user_text = ""
            content = msg.get("content", "")
            if isinstance(content, str):
                user_text = content[:120]
            elif isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "text":
                        user_text = b.get("text", "")[:120]
                        break

            session.turns.append(Turn(
                index=turn_idx, role="user", text_preview=user_text
            ))
            turn_idx += 1
            current_turn = None
            continue

        # tool_result user messages — skip (part of current assistant turn)
        if rec_type == "user":
            continue

        # Assistant message — merge into current turn
        if rec_type == "assistant":
            usage = msg.get("usage", {})

            if current_turn is None:
                current_turn = Turn(index=turn_idx, role="assistant")

            # Each assistant message is a separate API call.
            # Accumulate output tokens and track the max input (which grows).
            out = usage.get("output_tokens", 0)
            current_turn.output_tokens += out
            current_turn.api_calls += 1

            # Input tokens: take the max (context grows with each call)
            inp = (
                usage.get("input_tokens", 0)
                + usage.get("cache_read_input_tokens", 0)
                + usage.get("cache_creation_input_tokens", 0)
            )
            if inp > current_turn.input_tokens:
                current_turn.input_tokens = inp
                current_turn.cache_read_tokens = usage.get("cache_read_input_tokens", 0)
                current_turn.cache_write_tokens = usage.get("cache_creation_input_tokens", 0)

            # Parse content blocks
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type", "")

                    if btype == "thinking":
                        thinking_text = block.get("thinking", "")
                        current_turn.thinking_tokens += len(thinking_text) // 4

                    elif btype == "tool_use":
                        tc = _parse_tool_use(block)
                        current_turn.tool_calls.append(tc)

                    elif btype == "text":
                        text = block.get("text", "")
                        if text.strip() and not current_turn.text_preview:
                            current_turn.text_preview = text[:120]

    # Flush last turn
    if current_turn is not None:
        session.turns.append(current_turn)

    # Load sub-agent data if available
    _load_subagent_data(path, session)

    session.compute_totals()
    return session


def _load_subagent_data(session_path: str, session: Session):
    """Load sub-agent JSONL files and attach as children to Agent tool calls."""
    p = Path(session_path)
    session_dir = p.parent / p.stem
    subagents_dir = session_dir / "subagents"
    if not subagents_dir.exists():
        return

    agent_data = {}
    for meta_file in sorted(subagents_dir.glob("*.meta.json")):
        agent_id = meta_file.stem.replace(".meta", "")
        jsonl_file = subagents_dir / f"{agent_id}.jsonl"
        if not jsonl_file.exists():
            continue
        sub_lines = jsonl_file.read_text().strip().split("\n")
        sub_records = [json.loads(l) for l in sub_lines if l.strip()]
        children = []
        total_out = 0
        for rec in sub_records:
            if rec.get("type") != "assistant":
                continue
            msg = rec.get("message", {})
            if not isinstance(msg, dict):
                continue
            usage = msg.get("usage", {})
            out = usage.get("output_tokens", 0)
            total_out += out
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        children.append(_parse_tool_use(block))
        agent_data[agent_id] = {"children": children, "output_tokens": total_out}

    # Attach to Agent tool calls in order
    agent_ids = sorted(agent_data.keys())
    agent_tool_idx = 0
    for turn in session.turns:
        for tc in turn.tool_calls:
            if tc.name == "Agent" and agent_tool_idx < len(agent_ids):
                aid = agent_ids[agent_tool_idx]
                data = agent_data[aid]
                tc.children = data["children"]
                tc.output_tokens = data["output_tokens"]
                agent_tool_idx += 1


def _parse_tool_use(block: dict) -> ToolCall:
    """Parse a tool_use content block into a ToolCall."""
    name = block.get("name", "unknown_tool")
    inp = block.get("input", {})
    input_str = json.dumps(inp) if isinstance(inp, dict) else str(inp)
    estimated_input_tokens = len(input_str) // 4

    tc = ToolCall(
        name=name,
        input_tokens=estimated_input_tokens,
        input_preview=input_str[:300],
    )

    if name == "Agent" and isinstance(inp, dict):
        desc = inp.get("description", "")
        prompt = inp.get("prompt", "")
        tc.input_preview = f"[Agent] {desc}: {prompt[:150]}"

    return tc


def parse_teleport_export(path: str) -> Session:
    """Parse a teleport-analyzer export JSON file.

    Format: {"session": {...}, "events": [...], "exported_at": "...", "total_events": N}

    Teleport events don't include usage/token counts, so we estimate from content.
    Events include: system, user, assistant, tool_use_summary, tool_progress, result.
    """
    data = json.loads(Path(path).read_text())
    events = data.get("events", [])
    session_meta = data.get("session", {})

    session = Session()
    session.session_id = session_meta.get("id", "")

    # Extract model from session context or system event
    ctx = session_meta.get("session_context", {}) or {}
    session.model = ctx.get("model", "")

    turn_idx = 0
    current_turn = None

    for event in events:
        etype = event.get("type", "")

        if etype == "system":
            if not session.model:
                session.model = event.get("model", "")
            continue

        if etype == "user":
            # Check if real user message or tool_result
            msg = event.get("message", {})
            content = msg.get("content", "")

            is_tool_result = False
            user_text = ""
            if isinstance(content, str):
                user_text = content[:120]
            elif isinstance(content, list):
                has_only_tool_results = all(
                    isinstance(b, dict) and b.get("type") == "tool_result"
                    for b in content
                )
                if has_only_tool_results:
                    is_tool_result = True
                else:
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "text":
                            user_text = (b.get("text", "") or "")[:120]
                            break

            if not is_tool_result:
                # Real user message = turn boundary
                if current_turn is not None:
                    session.turns.append(current_turn)
                    turn_idx += 1
                session.turns.append(Turn(
                    index=turn_idx, role="user", text_preview=user_text
                ))
                turn_idx += 1
                current_turn = None
            continue

        if etype == "assistant":
            if current_turn is None:
                current_turn = Turn(index=turn_idx, role="assistant")
            current_turn.api_calls += 1

            msg = event.get("message", {})
            # Use exact usage data if available from API
            usage = msg.get("usage", {})
            has_usage = bool(usage.get("output_tokens"))
            if has_usage:
                current_turn.input_tokens += usage.get("input_tokens", 0)
                current_turn.output_tokens += usage.get("output_tokens", 0)
                current_turn.cache_read_tokens += usage.get("cache_read_input_tokens", 0)
                current_turn.cache_write_tokens += usage.get("cache_creation_input_tokens", 0)

            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type", "")

                    if btype == "thinking":
                        text = block.get("thinking", "") or ""
                        if not has_usage:
                            estimated = len(text) // 4
                            current_turn.thinking_tokens += estimated
                            current_turn.output_tokens += estimated

                    elif btype == "text":
                        text = block.get("text", "") or ""
                        if not has_usage:
                            estimated = len(text) // 4
                            current_turn.output_tokens += estimated
                        if text.strip() and not current_turn.text_preview:
                            current_turn.text_preview = text[:120]

                    elif btype == "tool_use":
                        tc = _parse_tool_use(block)
                        current_turn.tool_calls.append(tc)
                        if not has_usage:
                            current_turn.output_tokens += tc.input_tokens
            continue

        if etype == "result":
            # Extract duration from result events (contributed by 01AjHxHw)
            if current_turn is not None:
                current_turn.duration_ms += event.get("duration_ms", 0) or 0
                current_turn.duration_api_ms += event.get("duration_api_ms", 0) or 0
            continue

    # Flush last turn
    if current_turn is not None:
        session.turns.append(current_turn)

    session.compute_totals()
    return session


def parse_generic_json(path: str) -> Session:
    """Parse a generic agent session JSON file."""
    data = json.loads(Path(path).read_text())
    messages = data.get("messages", data if isinstance(data, list) else [])
    session = _parse_messages_generic(messages)
    session.model = data.get("model", "")
    session.session_id = data.get("session_id", "")
    return session


def _parse_messages_generic(messages: list[dict]) -> Session:
    """Parse generic message format."""
    session = Session()
    turn_idx = 0
    for msg in messages:
        if "message" in msg and isinstance(msg["message"], dict):
            inner = msg["message"]
            usage = inner.get("usage", {})
        else:
            inner = msg
            usage = msg.get("usage", {})

        role = inner.get("role", msg.get("type", "unknown"))
        turn = Turn(
            index=turn_idx, role=role,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            cache_read_tokens=usage.get("cache_read_input_tokens", 0),
            cache_write_tokens=usage.get("cache_creation_input_tokens", 0),
        )

        content = inner.get("content", "")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    btype = block.get("type", "")
                    if btype == "tool_use":
                        turn.tool_calls.append(_parse_tool_use(block))
                    elif btype == "thinking":
                        turn.thinking_tokens += len(block.get("thinking", "")) // 4
                    elif btype == "text":
                        text = block.get("text", "")
                        if text and not turn.text_preview:
                            turn.text_preview = text[:120]
        elif isinstance(content, str) and content:
            turn.text_preview = content[:120]

        session.turns.append(turn)
        turn_idx += 1
    session.compute_totals()
    return session


def parse_session(path: str) -> Session:
    """Auto-detect format and parse a session file."""
    p = Path(path)
    text = p.read_text().strip()

    # JSONL: multiple lines, each starting with {
    if "\n" in text:
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") in (
                    "queue-operation", "user", "assistant",
                    "attachment", "summary",
                ):
                    return parse_claude_code_jsonl(path)
            except json.JSONDecodeError:
                continue
            break  # only check lines until we find a valid JSON object

    try:
        data = json.loads(text)
        if isinstance(data, dict) and "events" in data and "session" in data:
            return parse_teleport_export(path)
        if isinstance(data, list):
            return _parse_messages_generic(data)
        return parse_generic_json(path)
    except json.JSONDecodeError as e:
        raise ValueError(f"Cannot parse {path}: {e}")
