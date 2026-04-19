#!/usr/bin/env python3
"""
Deterministic token optimizer — zero LLM cost.

Analyzes a session's tool call patterns and produces concrete,
actionable rules that can be injected into system prompts or
CLAUDE.md files to reduce token spend on future sessions.

All analysis is pure pattern matching and arithmetic — no LLM calls.

Can also be used with a cheap model (haiku) for natural-language
rule synthesis, but the core analysis is always deterministic.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter


@dataclass
class Rule:
    """A concrete optimization rule derived from session data."""
    id: str
    category: str  # "tool", "context", "agent", "pattern"
    title: str
    description: str
    evidence: str  # what data triggered this rule
    claude_md_directive: str  # exact text to add to CLAUDE.md
    estimated_savings_pct: float  # rough % of tokens saved
    priority: int  # 1=high, 2=med, 3=low


def analyze_session(path: str) -> list[Rule]:
    """Analyze a session JSONL and produce optimization rules."""
    p = Path(path)
    lines = p.read_text().strip().split("\n")
    records = [json.loads(l) for l in lines if l.strip()]

    rules = []
    rules.extend(_analyze_tool_patterns(records))
    rules.extend(_analyze_write_patterns(records))
    rules.extend(_analyze_context_growth(records))
    rules.extend(_analyze_subagent_patterns(records, path))
    rules.extend(_analyze_read_patterns(records))
    rules.extend(_analyze_bash_patterns(records))

    return sorted(rules, key=lambda r: r.priority)


def _extract_assistant_content(records: list[dict]) -> list[tuple[int, dict, dict]]:
    """Extract (index, usage, content_blocks) for assistant messages."""
    result = []
    for i, rec in enumerate(records):
        if rec.get("type") != "assistant":
            continue
        msg = rec.get("message", {})
        if not isinstance(msg, dict):
            continue
        usage = msg.get("usage", {})
        content = msg.get("content", [])
        if isinstance(content, list):
            result.append((i, usage, content))
    return result


def _analyze_tool_patterns(records: list[dict]) -> list[Rule]:
    """Detect tool call anti-patterns."""
    rules = []
    tool_counts = Counter()
    tool_sequences = []  # consecutive tool types

    for _, usage, content in _extract_assistant_content(records):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name", "")
                tool_counts[name] += 1
                tool_sequences.append(name)

    # Rule: Read followed immediately by Write to same file (could be Edit)
    read_then_write = 0
    for i in range(len(tool_sequences) - 1):
        if tool_sequences[i] == "Read" and tool_sequences[i + 1] == "Write":
            read_then_write += 1

    if read_then_write >= 2:
        rules.append(Rule(
            id="use-edit-not-write",
            category="tool",
            title="Use Edit instead of Read+Write",
            description=f"Found {read_then_write} Read→Write sequences. Edit sends only the diff.",
            evidence=f"{read_then_write} occurrences of Read immediately followed by Write",
            claude_md_directive="When modifying existing files, always use Edit (not Read+Write). Edit sends only the changed lines, saving ~60% of output tokens per file modification.",
            estimated_savings_pct=15.0,
            priority=1,
        ))

    # Rule: Too many sequential Bash calls (could be batched)
    bash_streaks = []
    current_streak = 0
    for t in tool_sequences:
        if t == "Bash":
            current_streak += 1
        else:
            if current_streak >= 3:
                bash_streaks.append(current_streak)
            current_streak = 0
    if current_streak >= 3:
        bash_streaks.append(current_streak)

    if bash_streaks:
        max_streak = max(bash_streaks)
        rules.append(Rule(
            id="batch-bash-calls",
            category="tool",
            title="Batch sequential Bash commands",
            description=f"Found {len(bash_streaks)} streak(s) of 3+ Bash calls (max {max_streak}). Chain with && or run in parallel.",
            evidence=f"Bash streaks: {bash_streaks}",
            claude_md_directive="Chain independent Bash commands with && in a single call. Run truly independent commands as parallel tool calls. Each separate Bash call costs a full context round-trip.",
            estimated_savings_pct=10.0,
            priority=2,
        ))

    return rules


def _analyze_write_patterns(records: list[dict]) -> list[Rule]:
    """Detect Write tool waste."""
    rules = []
    write_sizes = []

    for _, usage, content in _extract_assistant_content(records):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Write":
                inp = block.get("input", {})
                content_text = inp.get("content", "")
                write_sizes.append(len(content_text))

    if not write_sizes:
        return rules

    total_write_chars = sum(write_sizes)
    large_writes = [s for s in write_sizes if s > 3000]

    if large_writes:
        avg = sum(large_writes) // len(large_writes)
        rules.append(Rule(
            id="large-writes",
            category="tool",
            title="Large Write calls dominate output",
            description=f"{len(large_writes)} Write calls over 3KB (avg {avg:,} chars). Total: {total_write_chars:,} chars.",
            evidence=f"Write sizes: {sorted(write_sizes, reverse=True)[:5]}",
            claude_md_directive="For files over 50 lines, prefer Edit over Write. If creating a new large file, consider splitting into smaller logical files to reduce per-call token cost.",
            estimated_savings_pct=20.0,
            priority=1,
        ))

    return rules


def _analyze_context_growth(records: list[dict]) -> list[Rule]:
    """Detect context growth issues."""
    rules = []
    input_sizes = []

    for _, usage, _ in _extract_assistant_content(records):
        inp = (
            usage.get("input_tokens", 0)
            + usage.get("cache_read_input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
        )
        if inp > 0:
            input_sizes.append(inp)

    if len(input_sizes) < 3:
        return rules

    # Growth rate
    first_third = input_sizes[:len(input_sizes) // 3]
    last_third = input_sizes[-len(input_sizes) // 3:]
    avg_early = sum(first_third) // len(first_third)
    avg_late = sum(last_third) // len(last_third)
    growth = avg_late / max(avg_early, 1)

    if growth > 3.0:
        rules.append(Rule(
            id="context-explosion",
            category="context",
            title="Context grew {:.1f}x during session".format(growth),
            description=f"Input tokens went from ~{avg_early:,} to ~{avg_late:,}. Each tool call re-sends this.",
            evidence=f"First third avg: {avg_early:,}, Last third avg: {avg_late:,}",
            claude_md_directive="When context exceeds 80K tokens, proactively summarize findings before continuing. Avoid reading large files in full — use offset/limit to read only needed sections.",
            estimated_savings_pct=25.0,
            priority=1,
        ))

    # Cache efficiency
    cache_reads = []
    for _, usage, _ in _extract_assistant_content(records):
        cr = usage.get("cache_read_input_tokens", 0)
        total = (
            usage.get("input_tokens", 0) + cr
            + usage.get("cache_creation_input_tokens", 0)
        )
        if total > 0:
            cache_reads.append(cr / total)

    avg_cache_rate = sum(cache_reads) / len(cache_reads) if cache_reads else 0
    if avg_cache_rate < 0.7:
        rules.append(Rule(
            id="low-cache-rate",
            category="context",
            title=f"Cache hit rate only {avg_cache_rate * 100:.0f}%",
            description="Frequent cache invalidation wastes tokens re-processing the same context.",
            evidence=f"Average cache read ratio: {avg_cache_rate:.2f}",
            claude_md_directive="Avoid inserting large content blocks between turns. Keep system prompt and conversation history stable to maximize prompt caching.",
            estimated_savings_pct=15.0,
            priority=2,
        ))

    return rules


def _analyze_subagent_patterns(records: list[dict], session_path: str) -> list[Rule]:
    """Detect sub-agent waste."""
    rules = []
    p = Path(session_path)
    subagents_dir = p.parent / p.stem / "subagents"

    if not subagents_dir.exists():
        return rules

    agent_files = list(subagents_dir.glob("*.jsonl"))
    if not agent_files:
        return rules

    total_agent_tools = 0
    total_agent_bash = 0

    for af in agent_files:
        sub_lines = af.read_text().strip().split("\n")
        for line in sub_lines:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = rec.get("message", {})
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        total_agent_tools += 1
                        if block.get("name") == "Bash":
                            total_agent_bash += 1

    if total_agent_tools > 15:
        rules.append(Rule(
            id="subagent-tool-explosion",
            category="agent",
            title=f"Sub-agents made {total_agent_tools} tool calls ({total_agent_bash} Bash)",
            description="Each sub-agent tool call has its own context window. Bash calls in agents are especially wasteful — Glob/Grep are cheaper.",
            evidence=f"Across {len(agent_files)} sub-agents: {total_agent_tools} tools, {total_agent_bash} Bash",
            claude_md_directive='When spawning Agent sub-tasks, include "limit to 5-8 tool calls" and "use Glob/Grep instead of Bash for file searching" in the prompt. Prefer the Explore agent type for codebase questions.',
            estimated_savings_pct=10.0,
            priority=2,
        ))

    return rules


def _analyze_read_patterns(records: list[dict]) -> list[Rule]:
    """Detect redundant reads."""
    rules = []
    files_read = []

    for _, _, content in _extract_assistant_content(records):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Read":
                inp = block.get("input", {})
                fp = inp.get("file_path", "")
                has_limit = "limit" in inp
                files_read.append((fp, has_limit))

    # Count duplicate reads
    file_counts = Counter(fp for fp, _ in files_read)
    duplicates = {fp: count for fp, count in file_counts.items() if count > 1}

    if duplicates:
        total_dup_reads = sum(c - 1 for c in duplicates.values())
        rules.append(Rule(
            id="duplicate-reads",
            category="tool",
            title=f"{total_dup_reads} duplicate file reads",
            description=f"Files read multiple times: {list(duplicates.keys())[:3]}",
            evidence=f"Duplicates: {dict(list(duplicates.items())[:5])}",
            claude_md_directive="Before reading a file, check if you've already read it in this conversation. Store key information from reads in your response text so you don't need to re-read.",
            estimated_savings_pct=5.0,
            priority=3,
        ))

    # Full reads without limit
    full_reads = [fp for fp, has_limit in files_read if not has_limit]
    if len(full_reads) > 5:
        rules.append(Rule(
            id="full-file-reads",
            category="tool",
            title=f"{len(full_reads)} full file reads without limit",
            description="Reading entire files wastes tokens when you only need a section.",
            evidence=f"Full reads: {full_reads[:5]}",
            claude_md_directive="Use the limit and offset parameters when reading files. Read only the section you need, not the entire file.",
            estimated_savings_pct=8.0,
            priority=3,
        ))

    return rules


def _analyze_bash_patterns(records: list[dict]) -> list[Rule]:
    """Detect Bash anti-patterns."""
    rules = []
    bash_commands = []

    for _, _, content in _extract_assistant_content(records):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash":
                inp = block.get("input", {})
                cmd = inp.get("command", "")
                bash_commands.append(cmd)

    # Detect grep/find in Bash (should be Grep/Glob)
    grep_in_bash = [c for c in bash_commands if "grep " in c or "rg " in c]
    find_in_bash = [c for c in bash_commands if "find " in c or " ls " in c or c.startswith("ls ")]

    if grep_in_bash:
        rules.append(Rule(
            id="grep-in-bash",
            category="tool",
            title=f"{len(grep_in_bash)} grep/rg calls via Bash",
            description="The Grep tool is more token-efficient than Bash grep.",
            evidence=f"Commands: {[c[:50] for c in grep_in_bash[:3]]}",
            claude_md_directive="Never use `grep` or `rg` via Bash. Always use the Grep tool — it's optimized for permissions and returns structured results with less token overhead.",
            estimated_savings_pct=3.0,
            priority=3,
        ))

    if find_in_bash:
        rules.append(Rule(
            id="find-in-bash",
            category="tool",
            title=f"{len(find_in_bash)} find/ls calls via Bash",
            description="The Glob tool is more efficient for file discovery.",
            evidence=f"Commands: {[c[:50] for c in find_in_bash[:3]]}",
            claude_md_directive="Never use `find` or `ls` via Bash for file discovery. Use the Glob tool with patterns like '**/*.py' — it's faster and costs fewer tokens.",
            estimated_savings_pct=3.0,
            priority=3,
        ))

    return rules


def generate_claude_md(rules: list[Rule]) -> str:
    """Generate CLAUDE.md optimization directives from rules."""
    if not rules:
        return "# No optimizations needed"

    lines = ["# Token Optimization Rules", ""]
    lines.append("# Auto-generated from session analysis. Add to your CLAUDE.md")
    lines.append("# to reduce token consumption on future tasks.")
    lines.append("")

    for rule in rules:
        prio = {1: "HIGH", 2: "MED", 3: "LOW"}[rule.priority]
        lines.append(f"## [{prio}] {rule.title}")
        lines.append(f"# Saves ~{rule.estimated_savings_pct:.0f}% — {rule.description}")
        lines.append(rule.claude_md_directive)
        lines.append("")

    return "\n".join(lines)


def print_report(rules: list[Rule]):
    """Print a human-readable report."""
    if not rules:
        print("  ✅ No optimization opportunities detected")
        return

    total_savings = sum(r.estimated_savings_pct for r in rules)
    print(f"\n  Found {len(rules)} optimization rules (est. ~{min(total_savings, 60):.0f}% savings)\n")

    prio_icons = {1: "🔴", 2: "🟡", 3: "🔵"}
    for rule in rules:
        icon = prio_icons[rule.priority]
        print(f"  {icon} {rule.title}")
        print(f"     {rule.description}")
        print(f"     💡 {rule.claude_md_directive[:100]}")
        print()


if __name__ == "__main__":
    import sys

    # Parse args: filter out flags, find file path
    args = sys.argv[1:]
    flags = [a for a in args if a.startswith("--")]
    positional = [a for a in args if not a.startswith("--")]

    if positional:
        path = positional[0]
    else:
        # Auto-find current session
        claude_dir = Path.home() / ".claude" / "projects"
        jsonl_files = sorted(
            [f for f in claude_dir.rglob("*.jsonl") if "subagents" not in str(f)],
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not jsonl_files:
            print("No session found", file=sys.stderr)
            sys.exit(1)
        path = str(jsonl_files[0])

    rules = analyze_session(path)
    print_report(rules)

    if "--claude-md" in sys.argv:
        md = generate_claude_md(rules)
        out = Path("CLAUDE-optimized.md")
        out.write_text(md)
        print(f"\n  📝 Written to {out}")
    elif rules:
        print("  Run with --claude-md to generate CLAUDE.md directives")
