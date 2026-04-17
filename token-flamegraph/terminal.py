"""
Terminal-based rendering of the token visualization dashboard.

Renders directly in the terminal with ANSI colors, Unicode bar charts,
and structured layout — no browser needed.
"""

import shutil
from flamegraph import SessionViz, session_to_viz, ToolSpan
from parser import Session


# ANSI color codes
COLORS = {
    "thinking": "\033[91m",   # red
    "text":     "\033[94m",   # blue
    "read":     "\033[92m",   # green
    "write":    "\033[93m",   # yellow
    "bash":     "\033[95m",   # magenta
    "search":   "\033[32m",   # dark green
    "agent":    "\033[31m",   # dark red
    "other":    "\033[96m",   # cyan
    "cache":    "\033[90m",   # gray
    "fresh":    "\033[37m",   # light gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Bar characters
FULL_BLOCK = "█"
LIGHT_BLOCK = "░"
MED_BLOCK = "▒"
DARK_BLOCK = "▓"


def _c(category: str, text: str) -> str:
    """Colorize text by category."""
    color = COLORS.get(category, "")
    return f"{color}{text}{RESET}" if color else text


def _bar(value: int, max_val: int, category: str, width: int) -> str:
    """Render a colored bar."""
    if max_val == 0:
        return ""
    filled = max(0, int(value / max_val * width))
    return _c(category, FULL_BLOCK * filled)


def _fmt(n: int) -> str:
    """Format number with commas."""
    return f"{n:,}"


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n * 100 / total:.1f}%"


def render_terminal(session: Session, title: str = "Token Flamegraph") -> str:
    """Render the full dashboard as a string with ANSI colors."""
    viz = session_to_viz(session)
    term_width = min(shutil.get_terminal_size().columns, 120)
    bar_width = max(30, term_width - 50)
    lines = []

    def ln(s=""):
        lines.append(s)

    # Header
    ln(f"{BOLD}{'═' * term_width}{RESET}")
    ln(f"{BOLD}  {title}{RESET}")
    if viz.model:
        ln(f"  {DIM}Model: {viz.model}{RESET}")
    ln(f"{BOLD}{'═' * term_width}{RESET}")

    # Stats
    cache_pct = _pct(viz.total_cache, viz.total_input)
    active_turns = [t for t in viz.turns if t.output_tokens > 0]
    avg_score = sum(t.efficiency_score for t in active_turns) / len(active_turns) if active_turns else 0
    if avg_score >= 70:
        score_color = "\033[92m"
    elif avg_score >= 40:
        score_color = "\033[93m"
    else:
        score_color = "\033[91m"

    ln()
    ln(f"  {BOLD}Output:{RESET} {_fmt(viz.total_output)}    "
       f"{BOLD}Thinking:{RESET} {_fmt(viz.total_thinking)}    "
       f"{BOLD}Tool Calls:{RESET} {viz.num_tool_calls}    "
       f"{BOLD}Turns:{RESET} {len(active_turns)}    "
       f"{BOLD}Score:{RESET} {score_color}⚡{avg_score:.0f}{RESET}")
    # Cost estimation (Anthropic pricing per MTok)
    # Opus: input $3, cached input $0.30, output $15
    # Sonnet: input $3, cached input $0.30, output $15
    fresh_input = viz.total_input - viz.total_cache
    cost_input = (fresh_input / 1_000_000) * 3.0
    cost_cached = (viz.total_cache / 1_000_000) * 0.30
    cost_output = (viz.total_output / 1_000_000) * 15.0
    cost_total = cost_input + cost_cached + cost_output
    cost_no_cache = ((viz.total_input / 1_000_000) * 3.0) + cost_output
    saved = cost_no_cache - cost_total

    ln(f"  {BOLD}Input:{RESET}  {_fmt(viz.total_input)}    "
       f"{BOLD}Cached:{RESET} {_fmt(viz.total_cache)} ({cache_pct})    "
       f"{BOLD}Cost:{RESET} ${cost_total:.2f} (saved ${saved:.2f} from cache)")

    # Timeline waterfall
    ln()
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")
    ln(f"  {BOLD}TIMELINE — Output Tokens per Turn{RESET}")
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")

    max_out = max((t.output_tokens for t in viz.turns), default=1)

    for turn in viz.turns:
        if turn.output_tokens == 0:
            continue

        # Build colored bar segments
        segments = []
        if turn.thinking_tokens > 0:
            segments.append(("thinking", turn.thinking_tokens))
        for ts in turn.tool_spans:
            segments.append((ts.category, ts.total_tokens()))
        text_tok = max(0, turn.output_tokens - turn.thinking_tokens - turn.tool_tokens)
        if text_tok > 0:
            segments.append(("text", text_tok))

        # Render multi-colored bar
        bar_str = ""
        for cat, tok in segments:
            w = max(1, int(tok / max_out * bar_width)) if tok > 0 else 0
            bar_str += _c(cat, FULL_BLOCK * w)

        # Efficiency score with color
        score = turn.efficiency_score
        if score >= 70:
            score_color = "\033[92m"  # green
        elif score >= 40:
            score_color = "\033[93m"  # yellow
        else:
            score_color = "\033[91m"  # red
        score_str = f"{score_color}{score:4.0f}{RESET}"

        ln()
        ln(f"  {BOLD}Turn {turn.index:>2d}{RESET} │{bar_str}│ {_fmt(turn.output_tokens):>7s} tok  ⚡{score_str}")

        # Tool list
        if turn.tool_spans:
            tool_names = []
            for ts in turn.tool_spans:
                short_name = ts.name
                if len(short_name) > 30:
                    short_name = short_name[:28] + ".."
                tool_names.append(_c(ts.category, short_name))
            # Show up to 6 tools
            shown = tool_names[:6]
            extra = len(tool_names) - 6
            tool_line = ", ".join(shown)
            if extra > 0:
                tool_line += f" {DIM}+{extra} more{RESET}"
            ln(f"         │ {tool_line}")

        # Sub-agent children
        for ts in turn.tool_spans:
            if ts.children:
                child_names = [_c(c.category, c.name) for c in ts.children[:6]]
                more = f" {DIM}+{len(ts.children) - 6} more{RESET}" if len(ts.children) > 6 else ""
                agent_name = ts.name[:40]
                ln(f"         │  └─ {_c('agent', agent_name)}")
                ln(f"         │     {', '.join(child_names)}{more}")

    # Output breakdown
    ln()
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")
    ln(f"  {BOLD}OUTPUT TOKEN BREAKDOWN{RESET}")
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")

    categories = [
        ("Thinking", viz.total_thinking, "thinking"),
        ("Text output", viz.total_text, "text"),
    ]
    cat_names = {
        "read": "File reads", "write": "File writes", "bash": "Shell commands",
        "search": "Search", "agent": "Sub-agents", "other": "Other tools"
    }
    for cat, tokens in sorted(viz.tool_category_tokens.items(), key=lambda x: -x[1]):
        categories.append((cat_names.get(cat, cat), tokens, cat))

    total_cat = sum(c[1] for c in categories)
    max_cat = max(c[1] for c in categories) if categories else 1

    for name, tokens, cat in categories:
        b = _bar(tokens, max_cat, cat, 35)
        pct = _pct(tokens, total_cat)
        ln(f"  {name:<16s} {b} {_fmt(tokens):>7s} ({pct:>5s})")

    # Wall time per turn (only when duration data is available, e.g. teleport exports)
    # Contributed by session 01AjHxHw
    if any(t.duration_ms > 0 for t in viz.turns):
        ln()
        ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")
        ln(f"  {BOLD}WALL TIME PER TURN{RESET}")
        ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")

        max_dur = max((t.duration_ms for t in viz.turns), default=1)
        total_wall = sum(t.duration_ms for t in viz.turns)
        total_api = sum(t.duration_api_ms for t in viz.turns)
        total_overhead = total_wall - total_api

        for turn in viz.turns:
            if turn.duration_ms == 0:
                continue
            api_ms = turn.duration_api_ms
            overhead_ms = turn.duration_ms - api_ms
            api_bar = _bar(api_ms, max_dur, "thinking", 30)
            overhead_bar = _bar(overhead_ms, max_dur, "bash", 10)
            model_pct = api_ms * 100 // max(turn.duration_ms, 1)
            secs = turn.duration_ms / 1000
            ln(f"  T{turn.index:<3d} {api_bar}{overhead_bar} {secs:>6.1f}s ({model_pct}% model)")

        wall_s = total_wall / 1000
        api_s = total_api / 1000
        over_s = total_overhead / 1000
        ln(f"  {DIM}Total: {wall_s:.1f}s wall / {api_s:.1f}s model / {over_s:.1f}s overhead{RESET}")

    # Context growth
    ln()
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")
    ln(f"  {BOLD}INPUT COST PER TURN{RESET}")
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")

    max_input = max((t.input_tokens for t in viz.turns), default=1)
    for turn in viz.turns:
        if turn.input_tokens == 0:
            continue
        cache_pct_val = turn.cache_read_tokens * 100 // max(turn.input_tokens, 1)
        cache_bar = _bar(turn.cache_read_tokens, max_input, "cache", 40)
        fresh_bar = _bar(turn.fresh_input_tokens, max_input, "fresh", 40)
        ln(f"  T{turn.index:<3d} {cache_bar}{fresh_bar} {_fmt(turn.input_tokens):>7s} ({cache_pct_val}% {DIM}cached{RESET})")

    # Top tools
    ln()
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")
    ln(f"  {BOLD}TOP TOKEN CONSUMERS{RESET}")
    ln(f"  {DIM}{'─' * (term_width - 4)}{RESET}")

    if viz.top_tools:
        max_tool = viz.top_tools[0][1]
        for name, tokens in viz.top_tools[:10]:
            short = name[:42]
            # Detect category from name
            cat = "other"
            if name.startswith("Read"): cat = "read"
            elif name.startswith("Edit") or name.startswith("Write"): cat = "write"
            elif name.startswith("Bash"): cat = "bash"
            elif name.startswith("Grep") or name.startswith("Glob"): cat = "search"
            elif name.startswith("Agent"): cat = "agent"
            b = _bar(tokens, max_tool, cat, 30)
            ln(f"  {short:<44s} {b} {_fmt(tokens):>6s}")

    ln()
    ln(f"{BOLD}{'═' * term_width}{RESET}")

    # Legend
    legend_items = [
        ("thinking", "Thinking"), ("text", "Text"), ("write", "Write"),
        ("read", "Read"), ("bash", "Shell"), ("search", "Search"), ("agent", "Agent"),
    ]
    legend = "  ".join(f"{_c(cat, FULL_BLOCK * 2)} {name}" for cat, name in legend_items)
    ln(f"  {legend}")
    ln()

    return "\n".join(lines)
