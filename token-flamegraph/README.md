# Token Flamegraph

Visualize how a coding agent spends its token budget. Understand where tokens go across thinking, tool calls, and text output — turn by turn.

## Why not a literal flamegraph?

Traditional flamegraphs work for deep call stacks (20+ levels) with no temporal ordering. Agent sessions are shallow (3-4 levels), temporal order matters, and input context tokens dominate the view, hiding the interesting output work. This tool uses a **timeline waterfall** instead.

## What it shows

1. **Timeline waterfall** — each turn is a row, segmented by thinking / tool calls / text. Toggle to show input context tokens. Expand to see individual tool calls with sub-agent nesting.
2. **Output token donut** — aggregate breakdown of what the agent produced: thinking vs. tools vs. text.
3. **Input cost chart** — context token growth per turn with cache hit ratio.
4. **Top consumers table** — which specific tool calls consumed the most tokens.

## Usage

```bash
# Generate a demo visualization
python cli.py --demo -o demo.html

# Parse a real session
python cli.py session.json -o report.html --title "Fix auth bug"

# Open directly in browser
python cli.py session.json --open
```

## Input Formats

**Claude Code JSONL** — one JSON message per line with `usage` fields.

**Generic JSON** — `{"model": "...", "messages": [...]}` with `usage` per message.

## Interactive Features

- **Toggle context** — show/hide input tokens to focus on output work
- **Expand tool calls** — see individual tools as nested spans under each turn
- **Hover tooltips** — token counts, percentages, categories
- **Sub-agent nesting** — Agent tool children shown as indented tree

Zero dependencies. Single self-contained HTML file.
