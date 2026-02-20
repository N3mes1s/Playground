"""
agent.py - LLM Agent that executes tools inside Chrome's sandbox.

This is the main prototype: an AI agent powered by Claude that can execute
bash commands, read/write files, and perform other operations - all inside
Chrome's actual seccomp-BPF sandbox. Every syscall is traced and analyzed.

Architecture:
  ┌──────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
  │  Claude API   │────>│  Agent (Python)       │────>│  Chrome Sandbox      │
  │  (tool calls) │<────│  Tool routing +       │<────│  (seccomp-BPF +      │
  │               │     │  syscall analysis     │     │  ptrace tracing)     │
  └──────────────┘     └──────────────────────┘     └──────────────────────┘

The agent receives tool calls from Claude, executes them inside the Chrome
sandbox, captures the results AND a full syscall trace, then returns both
to the model so it can reason about what happened at the OS level.
"""

import json
import os
import sys
import textwrap
from dataclasses import dataclass, field

import anthropic

from chrome_sandbox import ChromeSandbox, PolicyLevel, ExecPolicy, SandboxResult


# ─── Tool Definitions (Claude tool_use format) ─────────────────────────────

TOOLS = [
    {
        "name": "bash",
        "description": (
            "Execute a bash command inside Chrome's seccomp-BPF sandbox. "
            "The command runs in an isolated process with syscall filtering. "
            "Returns stdout, stderr, exit code, and a full syscall trace."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read a file from the filesystem, inside the sandbox. "
            "Returns file contents and syscall trace of all OS operations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to read",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": (
            "Write content to a file, inside the sandbox. "
            "Returns success/failure and syscall trace."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to write to",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_dir",
        "description": (
            "List files in a directory, inside the sandbox. "
            "Returns directory listing and syscall trace."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path to list",
                }
            },
            "required": ["path"],
        },
    },
]


# ─── Syscall Analysis ──────────────────────────────────────────────────────

def analyze_syscalls(syscall_log: list) -> dict:
    """Analyze a syscall trace and produce a security summary."""
    if not syscall_log:
        return {"summary": "No syscalls traced", "risk_level": "NONE", "details": []}

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_name = {}
    for sc in syscall_log:
        risk = sc.get("risk", "LOW")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        name = sc.get("name", f"syscall#{sc.get('nr', '?')}")
        by_name[name] = by_name.get(name, 0) + 1

    # Determine overall risk
    if risk_counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif risk_counts["HIGH"] > 0:
        overall = "HIGH"
    elif risk_counts["MEDIUM"] > 0:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    # Top syscalls
    top = sorted(by_name.items(), key=lambda x: -x[1])[:10]

    details = []
    for sc in syscall_log:
        if sc.get("risk") in ("CRITICAL", "HIGH"):
            details.append(
                f"  {sc.get('name', '?')} (risk: {sc.get('risk')}) "
                f"args: {sc.get('args', [])[:3]}"
            )

    return {
        "summary": (
            f"{len(syscall_log)} syscalls: "
            f"{risk_counts['CRITICAL']} critical, {risk_counts['HIGH']} high, "
            f"{risk_counts['MEDIUM']} medium, {risk_counts['LOW']} low"
        ),
        "risk_level": overall,
        "top_syscalls": top,
        "high_risk_details": details[:20],
    }


# ─── Tool Execution ───────────────────────────────────────────────────────

def execute_tool(sandbox: ChromeSandbox, tool_name: str, tool_input: dict) -> str:
    """Execute a tool inside the Chrome sandbox and return formatted result."""

    if tool_name == "bash":
        cmd = tool_input["command"]
        result = sandbox.run(cmd)

    elif tool_name == "read_file":
        path = tool_input["path"]
        result = sandbox.run(f"cat {path!r}")

    elif tool_name == "write_file":
        path = tool_input["path"]
        content = tool_input.get("content", "")
        if not content:
            return json.dumps({"error": "write_file requires 'content' parameter", "exit_code": 1})
        # Use heredoc with single-quoted delimiter (no expansion, no escaping needed)
        # The only thing that could break this is the content containing the exact
        # delimiter string on its own line, so we use a unique one.
        delimiter = "SANDBOX_WRITE_EOF_7f3a9c"
        result = sandbox.run(f"cat > {path!r} << '{delimiter}'\n{content}\n{delimiter}")

    elif tool_name == "list_dir":
        path = tool_input["path"]
        result = sandbox.run(f"ls -la {path!r}")

    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    # Analyze the syscall trace
    analysis = analyze_syscalls(result.syscall_log)

    return json.dumps({
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "syscall_analysis": analysis,
        "duration_seconds": round(result.duration_seconds, 4),
        "num_syscalls": result.num_syscalls_total,
    }, indent=2)


# ─── Agent Loop ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an AI agent running inside Chrome's seccomp-BPF sandbox. Every tool \
call you make executes inside an isolated process with syscall filtering and \
full ptrace-based tracing.

After each tool call, you receive not just the output but also a syscall \
analysis showing every OS-level operation that occurred. Use this to:
1. Understand the security implications of your actions
2. Verify that the sandbox is properly constraining operations
3. Report any interesting security observations

You have these tools:
- bash: Run shell commands (inside the sandbox)
- read_file: Read file contents (inside the sandbox)
- write_file: Write files (inside the sandbox)
- list_dir: List directory contents (inside the sandbox)

Be concise but thorough. When reporting results, mention notable syscall \
activity if relevant (e.g., network attempts, file access patterns)."""


def run_agent(user_message: str, policy: PolicyLevel = PolicyLevel.TRACE_ALL,
              readonly_paths: list[str] | None = None,
              network_enabled: bool = False):
    """Run the sandboxed agent with the given user message."""

    client = anthropic.Anthropic()
    sandbox = ChromeSandbox(
        policy=policy,
        exec_policy=ExecPolicy.BROKERED,
        readonly_paths=readonly_paths,
        network_enabled=network_enabled,
    )

    print(f"\n{'='*70}")
    print(f"Chrome Sandbox Agent")
    print(f"Policy: {policy.name}")
    print(f"Kernel: {ChromeSandbox.kernel_version()}")
    print(f"seccomp-BPF: {'available' if ChromeSandbox.has_seccomp_bpf() else 'NOT available'}")
    print(f"{'='*70}")
    print(f"\nUser: {user_message}\n")

    messages = [{"role": "user", "content": user_message}]

    # Agent loop: keep going until the model stops making tool calls
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Process the response
        assistant_content = response.content
        has_tool_use = any(block.type == "tool_use" for block in assistant_content)

        # Print text blocks
        for block in assistant_content:
            if block.type == "text":
                print(f"Agent: {block.text}\n")

        if not has_tool_use or response.stop_reason == "end_turn":
            break

        # Execute tool calls
        messages.append({"role": "assistant", "content": assistant_content})
        tool_results = []

        for block in assistant_content:
            if block.type != "tool_use":
                continue

            print(f"  [Tool: {block.name}]")
            if block.name == "bash":
                print(f"  Command: {block.input.get('command', '')}")
            elif block.name == "read_file":
                print(f"  Path: {block.input.get('path', '')}")
            elif block.name == "write_file":
                print(f"  Path: {block.input.get('path', '')}")
            elif block.name == "list_dir":
                print(f"  Path: {block.input.get('path', '')}")

            # Execute inside Chrome sandbox
            try:
                result_str = execute_tool(sandbox, block.name, block.input)
                result_data = json.loads(result_str)
            except Exception as e:
                result_str = json.dumps({"error": str(e), "exit_code": 1})
                result_data = json.loads(result_str)

            print(f"  Exit: {result_data.get('exit_code', '?')} | "
                  f"Syscalls: {result_data.get('num_syscalls', 0)} | "
                  f"Risk: {result_data.get('syscall_analysis', {}).get('risk_level', '?')}")
            if result_data.get("stdout"):
                preview = result_data["stdout"][:200]
                if len(result_data["stdout"]) > 200:
                    preview += "..."
                print(f"  Output: {preview}")
            if result_data.get("error"):
                print(f"  Error: {result_data['error']}")
            print()

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_str,
            })

        messages.append({"role": "user", "content": tool_results})

    sandbox.close()
    print(f"{'='*70}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set.")
        print("Set it with: export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    if len(sys.argv) > 1:
        user_msg = " ".join(sys.argv[1:])
    else:
        user_msg = (
            "Explore the /tmp directory, create a test file, verify it exists, "
            "then check what system information is available. Report on the "
            "syscall patterns you observe."
        )

    # Choose policy based on env var or default to TRACE_ALL
    policy_name = os.environ.get("SANDBOX_POLICY", "TRACE_ALL")
    policy = PolicyLevel[policy_name]

    # Read-only paths for Python runtime
    readonly_paths = ["/usr/local/lib", "/usr/local/bin"]

    # Enable network if SANDBOX_NETWORK=1 or for API calls
    network_enabled = os.environ.get("SANDBOX_NETWORK", "0") == "1"

    run_agent(user_msg, policy=policy,
              readonly_paths=readonly_paths,
              network_enabled=network_enabled)


if __name__ == "__main__":
    main()
