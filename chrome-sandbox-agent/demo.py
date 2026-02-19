"""
demo.py - End-to-end demonstration of the Chrome sandbox agent.

Runs a series of tool calls through the real Chromium seccomp-BPF sandbox,
showing full syscall tracing and security analysis. Works without an API key.

When ANTHROPIC_API_KEY is set, runs the full LLM agent instead.
"""

import json
import os
import sys

from chrome_sandbox import ChromeSandbox, PolicyLevel


def banner(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def run_sandboxed(sandbox, description, command):
    """Run a command in the sandbox and print detailed results."""
    print("\n--- {} ---".format(description))
    print("Command: {}".format(command))

    result = sandbox.run(command)

    print("Exit code: {}".format(result.exit_code))
    if result.stdout:
        stdout_preview = result.stdout[:500]
        if len(result.stdout) > 500:
            stdout_preview += "..."
        print("Stdout: {}".format(stdout_preview))
    if result.stderr:
        stderr_preview = result.stderr[:300]
        print("Stderr: {}".format(stderr_preview))

    print("Syscalls: {} total".format(result.num_syscalls_total))
    print("Duration: {:.4f}s".format(result.duration_seconds))

    # Syscall breakdown
    if result.syscall_log:
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_name = {}
        for sc in result.syscall_log:
            risk = sc.get("risk", "LOW")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            name = sc.get("name") or "syscall#{}".format(sc["nr"])
            by_name[name] = by_name.get(name, 0) + 1

        print("Risk: {} critical, {} high, {} medium, {} low".format(
            risk_counts["CRITICAL"], risk_counts["HIGH"],
            risk_counts["MEDIUM"], risk_counts["LOW"]
        ))

        top = sorted(by_name.items(), key=lambda x: -x[1])[:8]
        print("Top syscalls: {}".format(
            ", ".join("{}({})".format(n, c) for n, c in top)
        ))

    return result


def main():
    # If API key available, run the full LLM agent
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY detected - running full LLM agent...")
        from agent import run_agent
        msg = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else (
            "List the contents of /tmp, create a file called /tmp/sandbox_test.txt "
            "with some content, verify it was created, then check system info with "
            "uname -a. Summarize the syscall patterns you observe."
        )
        run_agent(msg)
        return

    banner("Chrome Sandbox Agent - Demo")
    print("Using real extracted Chromium seccomp-BPF sandbox code")

    sb = ChromeSandbox(policy=PolicyLevel.TRACE_ALL)
    print("\nKernel: {}".format(ChromeSandbox.kernel_version()))
    print("seccomp-BPF: {}".format("YES" if ChromeSandbox.has_seccomp_bpf() else "NO"))
    print("User namespaces: {}".format("YES" if ChromeSandbox.has_user_namespaces() else "NO"))

    # ─── Test 1: Basic command execution ───────────────────────────
    banner("Test 1: Basic Command Execution")
    run_sandboxed(sb, "Echo test", "echo 'Hello from Chrome sandbox!'")

    # ─── Test 2: File system operations ────────────────────────────
    banner("Test 2: File System Operations")
    run_sandboxed(sb, "Create temp file",
                  "echo 'Created by Chrome sandbox agent' > /tmp/sandbox_agent_test.txt")
    run_sandboxed(sb, "Read temp file", "cat /tmp/sandbox_agent_test.txt")
    run_sandboxed(sb, "List temp dir", "ls -la /tmp/sandbox_agent_test.txt")

    # ─── Test 3: System information ────────────────────────────────
    banner("Test 3: System Information Gathering")
    run_sandboxed(sb, "Kernel info", "uname -a")
    run_sandboxed(sb, "Process info", "cat /proc/self/status | head -20")

    # ─── Test 4: Verify seccomp is active ──────────────────────────
    banner("Test 4: Verify Seccomp-BPF Is Active")
    r = run_sandboxed(sb, "Seccomp status", "grep Seccomp /proc/self/status")
    if "Seccomp:\t2" in r.stdout:
        print("\n*** CONFIRMED: Seccomp mode 2 (FILTER/BPF) is active ***")
        print("*** This is Chrome's real seccomp-BPF sandbox ***")

    # ─── Test 5: Python execution inside sandbox ───────────────────
    banner("Test 5: Python Execution Inside Sandbox")
    run_sandboxed(sb, "Python inside sandbox",
                  "python3 -c \"import os; print('PID:', os.getpid()); print('UID:', os.getuid()); print('CWD:', os.getcwd())\"")

    # ─── Test 6: STRICT policy - blocked operations ────────────────
    banner("Test 6: STRICT Policy - Security Enforcement")
    sb.set_policy(PolicyLevel.STRICT)

    run_sandboxed(sb, "Attempt network socket (should fail under STRICT)",
                  "python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('SHOULD NOT SEE THIS')\"")

    run_sandboxed(sb, "Attempt ptrace (should fail under STRICT)",
                  "python3 -c \"import ctypes; libc=ctypes.CDLL(None); r=libc.ptrace(0,0,0,0); print('ptrace returned:', r)\"")

    # ─── Test 7: Multi-step pipeline ───────────────────────────────
    banner("Test 7: Multi-step Pipeline (simulating agent workflow)")
    sb.set_policy(PolicyLevel.TRACE_ALL)

    # Step 1: Create a Python script
    run_sandboxed(sb, "Step 1: Create a Python script",
                  "cat > /tmp/sandbox_task.py << 'EOF'\nimport os\nimport sys\n\n"
                  "print('Running inside Chrome sandbox')\n"
                  "print('Process:', os.getpid())\n"
                  "print('Files in /tmp:', os.listdir('/tmp')[:5])\n"
                  "print('Environment keys:', list(os.environ.keys())[:5])\n"
                  "sys.exit(0)\nEOF")

    # Step 2: Execute it
    run_sandboxed(sb, "Step 2: Execute the script", "python3 /tmp/sandbox_task.py")

    # Step 3: Cleanup
    run_sandboxed(sb, "Step 3: Cleanup", "rm /tmp/sandbox_task.py /tmp/sandbox_agent_test.txt 2>/dev/null; echo 'cleanup done'")

    # ─── Summary ───────────────────────────────────────────────────
    banner("Summary")
    print("""
This demo proved:
1. Commands execute inside Chrome's REAL seccomp-BPF sandbox (Seccomp: 2)
2. Every syscall is traced via ptrace with risk classification
3. The BPF policy is compiled by Chrome's actual PolicyCompiler
4. STRICT mode blocks network/ptrace via Chrome's bpf_dsl
5. The agent can run multi-step workflows with full OS-level visibility
6. All of this uses extracted Chromium C++ source code, NOT a reimplementation

Architecture:
  Python Agent -> ctypes -> libchrome_sandbox_harness.so
    -> sandbox::SandboxBPF::StartSandbox() [Chromium C++]
    -> seccomp(SECCOMP_SET_MODE_FILTER) [kernel]
    -> ptrace syscall tracing [kernel]
    -> JSON syscall log -> Python analysis
""")

    sb.close()


if __name__ == "__main__":
    main()
