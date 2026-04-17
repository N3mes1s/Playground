"""
Generate a realistic demo session that simulates a coding agent working on a task.

This creates a Session object that looks like a real Claude Code session:
- Agent receives a task, thinks about it
- Reads files, searches code
- Spawns sub-agents for exploration
- Edits files, runs tests
- Iterates on failures
"""

from parser import Session, Turn, ToolCall


def generate_demo_session() -> Session:
    """Generate a realistic multi-turn coding agent session.

    Simulates: "Fix the authentication bug in the login endpoint"
    """
    session = Session(model="claude-opus-4-6", session_id="demo-session")

    # Turn 0: User request
    session.turns.append(Turn(
        index=0, role="user",
        input_tokens=150,
        text_preview="Fix the authentication bug in the login endpoint...",
    ))

    # Turn 1: Agent thinks and starts exploring
    session.turns.append(Turn(
        index=1, role="assistant",
        input_tokens=8500,
        output_tokens=1200,
        thinking_tokens=3800,
        cache_read_tokens=6000,
        text_preview="I'll investigate the authentication issue...",
        tool_calls=[
            ToolCall(
                name="Grep", input_tokens=80, output_tokens=350,
                input_preview='{"pattern": "login.*auth", "type": "ts"}',
            ),
            ToolCall(
                name="Grep", input_tokens=60, output_tokens=200,
                input_preview='{"pattern": "authenticate", "type": "ts"}',
            ),
        ],
    ))

    # Turn 2: Read relevant files
    session.turns.append(Turn(
        index=2, role="assistant",
        input_tokens=12000,
        output_tokens=800,
        thinking_tokens=2200,
        cache_read_tokens=9500,
        tool_calls=[
            ToolCall(
                name="Read", input_tokens=50, output_tokens=1800,
                input_preview='{"file_path": "/src/auth/login.ts"}',
            ),
            ToolCall(
                name="Read", input_tokens=50, output_tokens=1200,
                input_preview='{"file_path": "/src/auth/middleware.ts"}',
            ),
            ToolCall(
                name="Read", input_tokens=50, output_tokens=600,
                input_preview='{"file_path": "/src/types/user.ts"}',
            ),
        ],
    ))

    # Turn 3: Spawn exploration agent for deeper understanding
    session.turns.append(Turn(
        index=3, role="assistant",
        input_tokens=15000,
        output_tokens=400,
        thinking_tokens=4500,
        cache_read_tokens=12000,
        tool_calls=[
            ToolCall(
                name="Agent", input_tokens=300, output_tokens=2500,
                input_preview='[Agent] Explore how the session token validation works across the codebase',
                children=[
                    ToolCall(name="Grep", input_tokens=60, output_tokens=400),
                    ToolCall(name="Read", input_tokens=50, output_tokens=1500,
                             input_preview='{"file_path": "/src/auth/session.ts"}'),
                    ToolCall(name="Read", input_tokens=50, output_tokens=800,
                             input_preview='{"file_path": "/src/auth/token.ts"}'),
                    ToolCall(name="Grep", input_tokens=60, output_tokens=250),
                ],
            ),
        ],
    ))

    # Turn 4: Implement the fix
    session.turns.append(Turn(
        index=4, role="assistant",
        input_tokens=18000,
        output_tokens=2800,
        thinking_tokens=5200,
        cache_read_tokens=15000,
        text_preview="I found the bug. The token validation skips...",
        tool_calls=[
            ToolCall(
                name="Edit", input_tokens=400, output_tokens=100,
                input_preview='{"file_path": "/src/auth/middleware.ts"}',
            ),
            ToolCall(
                name="Edit", input_tokens=350, output_tokens=100,
                input_preview='{"file_path": "/src/auth/login.ts"}',
            ),
        ],
    ))

    # Turn 5: Run tests (first attempt - fails)
    session.turns.append(Turn(
        index=5, role="assistant",
        input_tokens=20000,
        output_tokens=600,
        thinking_tokens=1800,
        cache_read_tokens=17000,
        tool_calls=[
            ToolCall(
                name="Bash", input_tokens=80, output_tokens=3500,
                input_preview='{"command": "npm test -- --grep auth"}',
            ),
        ],
    ))

    # Turn 6: Fix test failure, iterate
    session.turns.append(Turn(
        index=6, role="assistant",
        input_tokens=22000,
        output_tokens=1500,
        thinking_tokens=3600,
        cache_read_tokens=19000,
        text_preview="Two tests failed because the mock needs updating...",
        tool_calls=[
            ToolCall(
                name="Read", input_tokens=50, output_tokens=900,
                input_preview='{"file_path": "/tests/auth.test.ts"}',
            ),
            ToolCall(
                name="Edit", input_tokens=500, output_tokens=100,
                input_preview='{"file_path": "/tests/auth.test.ts"}',
            ),
        ],
    ))

    # Turn 7: Run tests again (passes)
    session.turns.append(Turn(
        index=7, role="assistant",
        input_tokens=24000,
        output_tokens=800,
        thinking_tokens=1200,
        cache_read_tokens=21000,
        text_preview="All tests pass now.",
        tool_calls=[
            ToolCall(
                name="Bash", input_tokens=80, output_tokens=1200,
                input_preview='{"command": "npm test -- --grep auth"}',
            ),
        ],
    ))

    # Turn 8: Summary
    session.turns.append(Turn(
        index=8, role="assistant",
        input_tokens=25000,
        output_tokens=1800,
        thinking_tokens=800,
        cache_read_tokens=22000,
        text_preview="Fixed the authentication bug. The issue was...",
    ))

    session.compute_totals()
    return session
