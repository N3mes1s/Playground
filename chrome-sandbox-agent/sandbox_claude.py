#!/usr/bin/env python3
"""
sandbox-run: Run any command inside Chrome's seccomp-BPF sandbox.

Your current directory is bind-mounted as the workspace. The command runs
with full namespace isolation, chroot, capability dropping, and seccomp-BPF.
stdin/stdout/stderr stay connected to the terminal for interactive use.

Usage:
    sandbox-run claude                     # Claude Code, sandboxed
    sandbox-run python3                    # Python REPL, sandboxed
    sandbox-run bash                       # Shell, sandboxed
    sandbox-run --network curl example.com # With network access
    sandbox-run --no-workspace bash        # Ephemeral /tmp only

Security layers active:
    1. User namespace isolation
    2. PID namespace isolation
    3. IPC namespace isolation
    4. Network namespace (no network by default)
    5. Mount namespace + chroot (only workspace + system dirs visible)
    6. Capability dropping (no CAP_SYS_ADMIN, etc.)
    7. seccomp-BPF filter installed (TRACE_ALL)
"""

import argparse
import os
import sys
import textwrap
from pathlib import Path

# Ensure the package directory is importable
_pkg_dir = Path(__file__).parent.resolve()
if str(_pkg_dir) not in sys.path:
    sys.path.insert(0, str(_pkg_dir))

from chrome_sandbox import ChromeSandbox, PolicyLevel, ExecPolicy
from sandbox_config import SandboxConfig


def parse_args():
    parser = argparse.ArgumentParser(
        prog="sandbox-run",
        description="Run any command inside Chrome's seccomp-BPF sandbox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sandbox-run claude                     Run Claude Code sandboxed
              sandbox-run python3 app.py             Run Python sandboxed
              sandbox-run bash                       Interactive shell in sandbox
              sandbox-run --network node server.js   Node with network access
              sandbox-run --workspace ./proj claude   Use specific workspace
              sandbox-run --no-workspace bash         No workspace, /tmp only

            Security:
              All 7 isolation layers remain active. The sandboxed process can
              only see: workspace (rw), /bin, /lib, /usr, /etc (ro), /tmp (ephemeral).
              Network is disabled by default. Capabilities are dropped.

            Config: sandbox.config.json, SANDBOX_* env vars, or CLI flags.
        """),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run inside the sandbox",
    )
    parser.add_argument(
        "--workspace", "-w",
        default=None,
        help="Host directory to mount as workspace (default: current directory)",
    )
    parser.add_argument(
        "--no-workspace",
        action="store_true",
        help="Don't mount any workspace (ephemeral /tmp only)",
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="Enable network access inside the sandbox",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to sandbox.config.json",
    )
    parser.add_argument(
        "--policy",
        choices=["STRICT", "PERMISSIVE", "TRACE_ALL"],
        default=None,
        help="Seccomp-BPF policy level (default: STRICT)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print sandbox configuration before launching",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Must have a command to run
    command = args.command
    # Strip leading -- if present
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Error: no command specified.", file=sys.stderr)
        print("Usage: sandbox-run <command> [args...]", file=sys.stderr)
        print("Example: sandbox-run claude", file=sys.stderr)
        sys.exit(1)

    # Determine workspace
    workspace = None
    if args.no_workspace:
        workspace = None
    elif args.workspace:
        workspace = args.workspace
    else:
        workspace = os.getcwd()

    # Load config
    config = SandboxConfig.load(
        config_file=args.config,
        workspace=workspace if not args.no_workspace else "",
        network=args.network if args.network else None,
        policy=args.policy,
    )
    if args.no_workspace:
        config.workspace = None

    # Ensure workspace exists
    config.ensure_workspace()

    if args.verbose or os.environ.get("SANDBOX_VERBOSE"):
        print(f"\033[2m", file=sys.stderr, end="")
        print(f"sandbox-run: Chrome seccomp-BPF sandbox", file=sys.stderr)
        print(f"  Command:   {' '.join(command)}", file=sys.stderr)
        ws = config.workspace or "(none - ephemeral /tmp only)"
        print(f"  Workspace: {ws}", file=sys.stderr)
        print(f"  Network:   {'enabled' if config.network else 'disabled'}", file=sys.stderr)
        print(f"  Kernel:    {ChromeSandbox.kernel_version()}", file=sys.stderr)
        print(f"  seccomp:   {'active' if ChromeSandbox.has_seccomp_bpf() else 'NOT available'}", file=sys.stderr)
        print(f"\033[0m", file=sys.stderr, end="")

    # Initialize the sandbox
    sandbox = ChromeSandbox(
        policy=PolicyLevel.TRACE_ALL,
        exec_policy=ExecPolicy.BROKERED,
        readonly_paths=config.readonly_paths,
        allowed_paths=config.allowed_paths,
        network_enabled=config.network,
        workspace_dir=config.workspace,
        workspace_symlink=config.sandbox_workspace_path,
    )

    # Run the command interactively (stdio passthrough)
    exit_code = sandbox.run_interactive(command)

    sandbox.close()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
