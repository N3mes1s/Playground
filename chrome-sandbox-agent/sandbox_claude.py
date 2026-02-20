#!/usr/bin/env python3
"""
sandbox-claude: Interactive Claude agent with Chrome sandbox isolation.

Run it like you'd run `claude`, but every tool call executes inside Chrome's
real seccomp-BPF sandbox with full syscall tracing. Your current directory
becomes the workspace (bind-mounted read-write so files persist).

Usage:
    sandbox-claude                          # Interactive mode, CWD as workspace
    sandbox-claude --workspace ./project    # Use specific workspace
    sandbox-claude -p "build a web server"  # Single prompt, then exit
    sandbox-claude --policy STRICT          # Use Chrome's strict policy
    sandbox-claude --network                # Allow network access
"""

import argparse
import json
import os
import readline
import signal
import sys
import textwrap
from pathlib import Path

# Ensure the package directory is importable
_pkg_dir = Path(__file__).parent.resolve()
if str(_pkg_dir) not in sys.path:
    sys.path.insert(0, str(_pkg_dir))

import anthropic

from chrome_sandbox import ChromeSandbox, PolicyLevel, ExecPolicy
from sandbox_config import SandboxConfig
from agent import TOOLS, execute_tool, build_system_prompt


# ─── Terminal Colors ──────────────────────────────────────────────────────

class C:
    """Terminal color codes (auto-disabled if not a TTY)."""
    _enabled = sys.stdout.isatty()

    RESET   = "\033[0m"   if _enabled else ""
    BOLD    = "\033[1m"    if _enabled else ""
    DIM     = "\033[2m"    if _enabled else ""
    CYAN    = "\033[36m"   if _enabled else ""
    GREEN   = "\033[32m"   if _enabled else ""
    YELLOW  = "\033[33m"   if _enabled else ""
    RED     = "\033[31m"   if _enabled else ""
    MAGENTA = "\033[35m"   if _enabled else ""
    BLUE    = "\033[34m"   if _enabled else ""


# ─── Banner ───────────────────────────────────────────────────────────────

BANNER = f"""{C.BOLD}{C.CYAN}
  ╔═══════════════════════════════════════════════════╗
  ║  sandbox-claude                                   ║
  ║  Chrome seccomp-BPF sandboxed Claude agent        ║
  ╚═══════════════════════════════════════════════════╝{C.RESET}
"""

HELP_TEXT = f"""{C.DIM}Commands:
  /exit, /quit     Exit the session
  /status          Show sandbox status
  /clear           Clear conversation history
  /help            Show this help
  Ctrl+D           Exit
  Ctrl+C           Cancel current generation{C.RESET}
"""


# ─── Interactive Session ──────────────────────────────────────────────────

class SandboxClaude:
    """Interactive Claude session with sandboxed tool execution."""

    def __init__(self, config: SandboxConfig, model: str = "claude-sonnet-4-5-20250929"):
        self.config = config
        self.model = model
        self.messages: list[dict] = []
        self.client = anthropic.Anthropic()
        self.sandbox: ChromeSandbox | None = None
        self.tool_call_count = 0
        self.turn_count = 0
        self._interrupted = False

    def start(self):
        """Initialize the sandbox and print the banner."""
        self.config.ensure_workspace()

        policy = PolicyLevel[self.config.policy]
        self.sandbox = ChromeSandbox(
            policy=policy,
            exec_policy=ExecPolicy[self.config.exec_policy],
            readonly_paths=self.config.readonly_paths,
            allowed_paths=self.config.allowed_paths,
            network_enabled=self.config.network,
            workspace_dir=self.config.workspace,
            workspace_symlink=self.config.sandbox_workspace_path,
        )

        print(BANNER)
        print(f"{C.DIM}  Workspace:  {self.config.workspace or '(none - ephemeral /tmp only)'}")
        ws = self.sandbox.workspace_path
        if ws:
            print(f"  Sandbox:    {ws}")
        print(f"  Policy:     {self.config.policy}")
        print(f"  Network:    {'enabled' if self.config.network else 'disabled'}")
        print(f"  Kernel:     {ChromeSandbox.kernel_version()}")
        print(f"  seccomp:    {'active' if ChromeSandbox.has_seccomp_bpf() else 'NOT available'}")
        print(f"{C.RESET}")
        print(HELP_TEXT)

    def shutdown(self):
        """Clean up the sandbox."""
        if self.sandbox:
            self.sandbox.close()
            self.sandbox = None

    # ─── REPL ─────────────────────────────────────────────────────────────

    def repl(self):
        """Run the interactive read-eval-print loop."""
        # Set up readline history
        histfile = os.path.expanduser("~/.sandbox_claude_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)

        # Handle Ctrl+C gracefully
        original_sigint = signal.getsignal(signal.SIGINT)

        try:
            while True:
                try:
                    # Reset interrupt flag
                    self._interrupted = False
                    signal.signal(signal.SIGINT, self._handle_sigint_prompt)

                    # Read user input (supports multi-line with trailing \)
                    user_input = self._read_input()
                    if user_input is None:
                        # EOF (Ctrl+D)
                        print(f"\n{C.DIM}Goodbye!{C.RESET}")
                        break

                    user_input = user_input.strip()
                    if not user_input:
                        continue

                    # Handle slash commands
                    if user_input.startswith("/"):
                        if self._handle_command(user_input):
                            continue
                        else:
                            break  # /exit or /quit

                    # Send to Claude and handle response
                    signal.signal(signal.SIGINT, self._handle_sigint_generation)
                    self._chat(user_input)

                except KeyboardInterrupt:
                    print(f"\n{C.DIM}(interrupted){C.RESET}")
                    continue
                except EOFError:
                    print(f"\n{C.DIM}Goodbye!{C.RESET}")
                    break

        finally:
            signal.signal(signal.SIGINT, original_sigint)
            try:
                readline.write_history_file(histfile)
            except OSError:
                pass

    def run_single(self, prompt: str):
        """Run a single prompt (non-interactive mode)."""
        self._chat(prompt)

    # ─── Chat with Claude ─────────────────────────────────────────────────

    def _chat(self, user_message: str):
        """Send a message and handle the full agent loop (tools + responses)."""
        self.messages.append({"role": "user", "content": user_message})
        self.turn_count += 1

        system_prompt = build_system_prompt(
            self.sandbox.workspace_path if self.sandbox else None
        )

        # Agent loop: keep going until no more tool calls
        while True:
            if self._interrupted:
                print(f"\n{C.DIM}(generation cancelled){C.RESET}")
                break

            try:
                response = self._call_api(system_prompt)
            except anthropic.APIError as e:
                print(f"\n{C.RED}API error: {e}{C.RESET}")
                # Remove the dangling user message
                if self.messages and self.messages[-1]["role"] == "user":
                    self.messages.pop()
                break

            assistant_content = response.content
            has_tool_use = any(b.type == "tool_use" for b in assistant_content)

            # Print text blocks
            for block in assistant_content:
                if block.type == "text" and block.text.strip():
                    print(f"\n{C.BOLD}{block.text}{C.RESET}")

            if not has_tool_use or response.stop_reason == "end_turn":
                # Record assistant response and we're done
                self.messages.append({"role": "assistant", "content": assistant_content})
                break

            # Execute tool calls
            self.messages.append({"role": "assistant", "content": assistant_content})
            tool_results = []

            for block in assistant_content:
                if block.type != "tool_use":
                    continue

                if self._interrupted:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps({"error": "Cancelled by user", "exit_code": 130}),
                        "is_error": True,
                    })
                    continue

                result_str = self._execute_and_display(block)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_str,
                })

            self.messages.append({"role": "user", "content": tool_results})

        print()  # Blank line after response

    def _call_api(self, system_prompt: str):
        """Call the Claude API with streaming."""
        # Use streaming for real-time output
        with self.client.messages.stream(
            model=self.model,
            max_tokens=8192,
            system=system_prompt,
            tools=TOOLS,
            messages=self.messages,
        ) as stream:
            current_text = ""
            started_text = False

            for event in stream:
                if self._interrupted:
                    break

                if hasattr(event, 'type'):
                    if event.type == 'content_block_start':
                        if hasattr(event, 'content_block') and event.content_block.type == 'text':
                            started_text = True
                            sys.stdout.write(f"\n{C.BOLD}")
                            sys.stdout.flush()
                    elif event.type == 'content_block_delta':
                        if hasattr(event, 'delta') and hasattr(event.delta, 'text'):
                            sys.stdout.write(event.delta.text)
                            sys.stdout.flush()
                    elif event.type == 'content_block_stop':
                        if started_text:
                            sys.stdout.write(f"{C.RESET}")
                            sys.stdout.flush()
                            started_text = False

            response = stream.get_final_message()

        return response

    def _execute_and_display(self, block) -> str:
        """Execute a tool call and display progress."""
        self.tool_call_count += 1
        name = block.name
        inp = block.input

        # Display tool call
        if name == "bash":
            cmd = inp.get("command", "")
            display = cmd if len(cmd) <= 120 else cmd[:117] + "..."
            print(f"\n  {C.YELLOW}{name}{C.RESET} {C.DIM}{display}{C.RESET}")
        elif name in ("read_file", "list_dir"):
            print(f"\n  {C.YELLOW}{name}{C.RESET} {C.DIM}{inp.get('path', '')}{C.RESET}")
        elif name == "write_file":
            content = inp.get("content", "")
            lines = content.count("\n") + 1
            print(f"\n  {C.YELLOW}{name}{C.RESET} {C.DIM}{inp.get('path', '')} ({lines} lines){C.RESET}")
        else:
            print(f"\n  {C.YELLOW}{name}{C.RESET}")

        # Execute in sandbox
        try:
            result_str = execute_tool(self.sandbox, name, inp)
            result_data = json.loads(result_str)
        except Exception as e:
            result_str = json.dumps({"error": str(e), "exit_code": 1})
            result_data = {"error": str(e), "exit_code": 1}

        # Display result summary
        exit_code = result_data.get("exit_code", "?")
        num_sc = result_data.get("num_syscalls", 0)
        risk = result_data.get("syscall_analysis", {}).get("risk_level", "?")

        if exit_code == 0:
            status = f"{C.GREEN}ok{C.RESET}"
        else:
            status = f"{C.RED}exit {exit_code}{C.RESET}"

        risk_color = {
            "LOW": C.GREEN, "MEDIUM": C.YELLOW,
            "HIGH": C.RED, "CRITICAL": C.RED,
        }.get(risk, C.DIM)

        print(f"  {C.DIM}  -> {status} {C.DIM}| {num_sc} syscalls | risk: {risk_color}{risk}{C.RESET}")

        # Show stdout preview for non-write tools
        if name != "write_file" and result_data.get("stdout"):
            preview = result_data["stdout"].rstrip()
            lines = preview.split("\n")
            if len(lines) > 6:
                for line in lines[:5]:
                    truncated = line[:120] + "..." if len(line) > 120 else line
                    print(f"  {C.DIM}  {truncated}{C.RESET}")
                print(f"  {C.DIM}  ... ({len(lines) - 5} more lines){C.RESET}")
            elif preview:
                for line in lines:
                    truncated = line[:120] + "..." if len(line) > 120 else line
                    print(f"  {C.DIM}  {truncated}{C.RESET}")

        if result_data.get("stderr") and exit_code != 0:
            stderr_preview = result_data["stderr"][:200].rstrip()
            print(f"  {C.RED}  {stderr_preview}{C.RESET}")

        return result_str

    # ─── Input Handling ───────────────────────────────────────────────────

    def _read_input(self) -> str | None:
        """Read user input with prompt. Returns None on EOF."""
        try:
            line = input(f"{C.GREEN}> {C.RESET}")
            return line
        except EOFError:
            return None

    def _handle_command(self, cmd: str) -> bool:
        """Handle a slash command. Returns True to continue, False to exit."""
        cmd = cmd.lower().strip()

        if cmd in ("/exit", "/quit", "/q"):
            print(f"{C.DIM}Goodbye!{C.RESET}")
            return False

        elif cmd == "/clear":
            self.messages.clear()
            self.turn_count = 0
            print(f"{C.DIM}Conversation cleared.{C.RESET}")
            return True

        elif cmd == "/status":
            ws = self.config.workspace or "(none)"
            print(f"\n{C.CYAN}Sandbox Status:{C.RESET}")
            print(f"  Workspace:    {ws}")
            print(f"  Policy:       {self.config.policy}")
            print(f"  Network:      {'enabled' if self.config.network else 'disabled'}")
            print(f"  Turns:        {self.turn_count}")
            print(f"  Tool calls:   {self.tool_call_count}")
            print(f"  Messages:     {len(self.messages)}")
            print(f"  Model:        {self.model}")
            print()
            return True

        elif cmd == "/help":
            print(HELP_TEXT)
            return True

        else:
            print(f"{C.DIM}Unknown command: {cmd}. Type /help for commands.{C.RESET}")
            return True

    # ─── Signal Handlers ──────────────────────────────────────────────────

    def _handle_sigint_prompt(self, sig, frame):
        """Ctrl+C at the prompt - print newline."""
        print()
        raise KeyboardInterrupt

    def _handle_sigint_generation(self, sig, frame):
        """Ctrl+C during generation - set interrupted flag."""
        self._interrupted = True
        print(f"\n{C.DIM}(cancelling...){C.RESET}")


# ─── CLI Entry Point ──────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="sandbox-claude",
        description="Interactive Claude agent inside Chrome's seccomp-BPF sandbox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sandbox-claude                          Interactive mode, CWD as workspace
              sandbox-claude --workspace ./project    Use specific workspace
              sandbox-claude -p "build a web server"  Single prompt mode
              sandbox-claude --policy STRICT           Chrome's strict renderer policy
              sandbox-claude --network                 Allow network access
              sandbox-claude --no-workspace            No workspace (ephemeral /tmp only)

            Configuration priority: CLI flags > env vars > sandbox.config.json > defaults

            Environment variables:
              SANDBOX_WORKSPACE       Workspace directory
              SANDBOX_POLICY          Policy level (STRICT/PERMISSIVE/TRACE_ALL)
              SANDBOX_NETWORK         Enable network (1/true/yes)
              ANTHROPIC_API_KEY       Claude API key (required)
        """),
    )
    parser.add_argument(
        "-p", "--prompt",
        help="Run a single prompt and exit (non-interactive mode)",
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
        "--policy",
        choices=["STRICT", "PERMISSIVE", "TRACE_ALL"],
        default=None,
        help="Seccomp-BPF policy level (default: TRACE_ALL)",
    )
    parser.add_argument(
        "--network",
        action="store_true",
        default=None,
        help="Enable network access inside the sandbox",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to sandbox.config.json",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-5-20250929",
        help="Claude model to use (default: claude-sonnet-4-5-20250929)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Check API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(f"{C.RED}Error: ANTHROPIC_API_KEY not set.{C.RESET}")
        print(f"Set it with: export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    # Determine workspace:
    # --no-workspace -> None
    # --workspace DIR -> DIR
    # default -> CWD
    workspace = None
    if args.no_workspace:
        workspace = None
    elif args.workspace:
        workspace = args.workspace
    else:
        # Default: use current directory as workspace
        workspace = os.getcwd()

    # Load config (layered: file < env < CLI args)
    config = SandboxConfig.load(
        config_file=args.config,
        workspace=workspace if not args.no_workspace else "",
        policy=args.policy,
        network=args.network if args.network else None,
    )

    # Handle --no-workspace explicitly
    if args.no_workspace:
        config.workspace = None

    # Create the interactive session
    session = SandboxClaude(config=config, model=args.model)

    try:
        session.start()

        if args.prompt:
            # Single prompt mode
            session.run_single(args.prompt)
        else:
            # Interactive REPL
            session.repl()

    except KeyboardInterrupt:
        print(f"\n{C.DIM}Goodbye!{C.RESET}")
    finally:
        session.shutdown()


if __name__ == "__main__":
    main()
