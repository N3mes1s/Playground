"""
Convert a parsed Session into visualization-ready data structures.

Produces:
- Per-turn waterfall data (output token breakdown)
- Aggregate category breakdown
- Context growth over turns
- Tool call detail list
"""

import json
from dataclasses import dataclass, field
from parser import Session, Turn, ToolCall


@dataclass
class ToolSpan:
    """A tool call rendered as a span in the waterfall."""
    name: str
    tokens: int  # output tokens (input + output of the tool)
    category: str  # "read", "edit", "bash", "search", "agent", "other"
    children: list["ToolSpan"] = field(default_factory=list)
    preview: str = ""

    def total_tokens(self) -> int:
        return self.tokens + sum(c.total_tokens() for c in self.children)


@dataclass
class TurnData:
    """Visualization data for one assistant turn."""
    index: int
    thinking_tokens: int
    text_tokens: int
    tool_spans: list[ToolSpan]
    input_tokens: int
    cache_read_tokens: int
    fresh_input_tokens: int
    # Duration from teleport result events (ms)
    duration_ms: int = 0
    duration_api_ms: int = 0

    @property
    def output_tokens(self) -> int:
        """Total output-side tokens (what the agent chose to produce)."""
        return (
            self.thinking_tokens
            + self.text_tokens
            + sum(ts.total_tokens() for ts in self.tool_spans)
        )

    @property
    def tool_tokens(self) -> int:
        return sum(ts.total_tokens() for ts in self.tool_spans)

    @property
    def efficiency_score(self) -> float:
        """0-100 score: how efficiently this turn used tokens.

        Penalizes:
        - Write-heavy turns (Write is wasteful vs Edit)
        - High thinking-to-action ratio
        - Large output with few tools (verbose)
        - Low cache hit rate

        Rewards:
        - Edit usage over Write
        - High tool-to-output ratio (concise)
        - Good cache utilization
        """
        out = self.output_tokens
        if out == 0:
            return 0.0

        score = 100.0
        num_tools = len(self.tool_spans)

        # Penalty: insufficient data — short turns with <500 tokens get
        # capped at 80 since we can't meaningfully assess efficiency
        if out < 500:
            score = min(score, 80.0)

        # Penalty: Write-heavy (each Write token costs more than Edit)
        write_tokens = sum(
            ts.total_tokens() for ts in self.tool_spans
            if ts.name.startswith("Write")
        )
        if write_tokens > 0:
            write_ratio = write_tokens / out
            score -= write_ratio * 40

        # Penalty: high thinking ratio (>30% thinking = overthinking)
        think_ratio = self.thinking_tokens / out
        if think_ratio > 0.3:
            score -= (think_ratio - 0.3) * 50

        # Penalty: verbose output (>5K tokens with few tools = wall of text)
        if out > 5000 and num_tools < 3:
            score -= 20

        # Penalty: no tool calls at all (pure text generation, rarely efficient)
        if num_tools == 0 and out > 200:
            score -= 15

        # Penalty: low cache rate (under 80%)
        if self.input_tokens > 0:
            cache_rate = self.cache_read_tokens / self.input_tokens
            if cache_rate < 0.8:
                score -= (0.8 - cache_rate) * 30

        # Bonus: Edit usage (efficient modification)
        edit_tokens = sum(
            ts.total_tokens() for ts in self.tool_spans
            if ts.name.startswith("Edit")
        )
        if edit_tokens > 0 and out > 0:
            score += min(10, (edit_tokens / out) * 20)

        # Bonus: high tool density (concise, action-oriented)
        if out > 0 and num_tools > 0:
            density = num_tools / (out / 1000)
            score += min(10, density * 2)

        return round(max(0, min(100, score)), 1)


@dataclass
class SessionViz:
    """All visualization data for a session."""
    turns: list[TurnData]
    model: str
    session_id: str

    # Aggregates
    total_thinking: int = 0
    total_text: int = 0
    total_tool: int = 0
    total_input: int = 0
    total_cache: int = 0
    total_output: int = 0
    num_tool_calls: int = 0

    # Duration totals (from teleport result events)
    total_duration_ms: int = 0
    total_api_duration_ms: int = 0

    # Per-category tool breakdown
    tool_category_tokens: dict[str, int] = field(default_factory=dict)

    # Top tools by token usage
    top_tools: list[tuple[str, int]] = field(default_factory=list)


def session_to_viz(session: Session) -> SessionViz:
    """Convert a parsed session into visualization data."""
    turns = []
    tool_totals: dict[str, int] = {}
    category_totals: dict[str, int] = {}
    num_tools = 0

    for turn in session.turns:
        if turn.role != "assistant":
            continue

        tool_spans = [_tool_to_span(tc) for tc in turn.tool_calls]
        tool_tok = sum(ts.total_tokens() for ts in tool_spans)
        # Text tokens = total output minus thinking minus tool input estimates
        text_tok = max(0, turn.output_tokens - turn.thinking_tokens - sum(
            tc.input_tokens for tc in turn.tool_calls
        ))

        td = TurnData(
            index=turn.index,
            thinking_tokens=turn.thinking_tokens,
            text_tokens=text_tok,
            tool_spans=tool_spans,
            input_tokens=turn.input_tokens,
            cache_read_tokens=turn.cache_read_tokens,
            fresh_input_tokens=turn.input_tokens - turn.cache_read_tokens,
            duration_ms=turn.duration_ms,
            duration_api_ms=turn.duration_api_ms,
        )
        turns.append(td)

        # Accumulate tool stats
        for ts in tool_spans:
            _accumulate_tool(ts, tool_totals, category_totals)
            num_tools += 1
            num_tools += _count_children(ts)

    viz = SessionViz(
        turns=turns,
        model=session.model,
        session_id=session.session_id,
        total_thinking=sum(t.thinking_tokens for t in turns),
        total_text=sum(t.text_tokens for t in turns),
        total_tool=sum(t.tool_tokens for t in turns),
        total_input=sum(t.input_tokens for t in turns),
        total_cache=sum(t.cache_read_tokens for t in turns),
        total_output=sum(t.output_tokens for t in turns),
        total_duration_ms=sum(t.duration_ms for t in turns),
        total_api_duration_ms=sum(t.duration_api_ms for t in turns),
        num_tool_calls=num_tools,
        tool_category_tokens=category_totals,
        top_tools=sorted(tool_totals.items(), key=lambda x: -x[1])[:15],
    )
    return viz


def _tool_to_span(tc: ToolCall) -> ToolSpan:
    name = _tool_label(tc)
    cat = _tool_category(tc.name)
    children = [_tool_to_span(c) for c in tc.children]
    return ToolSpan(
        name=name,
        tokens=tc.input_tokens + tc.output_tokens,
        category=cat,
        children=children,
        preview=tc.input_preview[:100],
    )


def _tool_category(name: str) -> str:
    categories = {
        "Read": "read", "Grep": "search", "Glob": "search",
        "Edit": "write", "Write": "write",
        "Bash": "bash", "Agent": "agent",
    }
    return categories.get(name, "other")


def _tool_label(tc: ToolCall) -> str:
    name = tc.name
    preview = tc.input_preview
    if name in ("Read", "Edit", "Write") and "file_path" in preview:
        try:
            data = json.loads(preview)
            fp = data.get("file_path", "")
            short = fp.split("/")[-1] if "/" in fp else fp
            return f"{name}({short})"
        except (json.JSONDecodeError, TypeError):
            pass
    if name == "Bash" and "command" in preview:
        try:
            data = json.loads(preview)
            cmd = data.get("command", "")[:35]
            return f"Bash({cmd})"
        except (json.JSONDecodeError, TypeError):
            pass
    if name == "Agent":
        desc = preview.replace("[Agent] ", "")[:50]
        return f"Agent({desc})"
    return name


def _accumulate_tool(ts: ToolSpan, tool_totals: dict, cat_totals: dict):
    tool_totals[ts.name] = tool_totals.get(ts.name, 0) + ts.tokens
    cat_totals[ts.category] = cat_totals.get(ts.category, 0) + ts.tokens
    for child in ts.children:
        _accumulate_tool(child, tool_totals, cat_totals)


def _count_children(ts: ToolSpan) -> int:
    return sum(1 + _count_children(c) for c in ts.children)


def viz_to_json(viz: SessionViz) -> dict:
    """Serialize visualization data for embedding in HTML."""
    return {
        "turns": [
            {
                "index": t.index,
                "thinking": t.thinking_tokens,
                "text": t.text_tokens,
                "tools": [_span_to_dict(s) for s in t.tool_spans],
                "toolTokens": t.tool_tokens,
                "outputTokens": t.output_tokens,
                "inputTokens": t.input_tokens,
                "cacheRead": t.cache_read_tokens,
                "freshInput": t.fresh_input_tokens,
                "durationMs": t.duration_ms,
                "durationApiMs": t.duration_api_ms,
            }
            for t in viz.turns
        ],
        "totals": {
            "thinking": viz.total_thinking,
            "text": viz.total_text,
            "tool": viz.total_tool,
            "input": viz.total_input,
            "cache": viz.total_cache,
            "output": viz.total_output,
            "toolCalls": viz.num_tool_calls,
            "durationMs": viz.total_duration_ms,
            "durationApiMs": viz.total_api_duration_ms,
        },
        "categoryTokens": viz.tool_category_tokens,
        "topTools": [{"name": n, "tokens": t} for n, t in viz.top_tools],
        "model": viz.model,
    }


def _span_to_dict(ts: ToolSpan) -> dict:
    return {
        "name": ts.name,
        "tokens": ts.tokens,
        "totalTokens": ts.total_tokens(),
        "category": ts.category,
        "children": [_span_to_dict(c) for c in ts.children],
    }
