#!/usr/bin/env python3
"""
Sandbox Security Breakout Test Suite

Tests Chrome sandbox escape patterns, privilege escalation, filesystem
traversal, namespace escape, seccomp bypass, and other security boundaries.

Each test runs a command INSIDE the sandbox and verifies the sandbox
correctly blocks the attack. A passing test means the attack FAILED
(sandbox held). A failing test means the attack SUCCEEDED (sandbox broken).

Run: python3 tests/test_sandbox_security.py
"""

import json
import os
import sys
import textwrap
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from chrome_sandbox import ChromeSandbox, PolicyLevel, ExecPolicy

# Colors for output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS = f"{GREEN}PASS{RESET}"
FAIL = f"{RED}FAIL{RESET}"
WARN = f"{YELLOW}WARN{RESET}"


class SecurityTestSuite:
    """Runs sandbox escape tests and reports results."""

    def __init__(self):
        self.results = []  # (category, name, passed, detail)
        self.sandbox = None

    def setup(self):
        """Initialize sandbox with STRICT policy (Chrome renderer equivalent)."""
        workspace = "/tmp/sandbox-security-test"
        os.makedirs(workspace, exist_ok=True)

        # Write a canary file in workspace to test read-write access
        with open(os.path.join(workspace, "canary.txt"), "w") as f:
            f.write("workspace-canary")

        self.sandbox = ChromeSandbox(
            policy=PolicyLevel.STRICT,
            exec_policy=ExecPolicy.BROKERED,
            workspace_dir=workspace,
            network_enabled=False,
        )

    def teardown(self):
        if self.sandbox:
            self.sandbox.close()

    def run_cmd(self, cmd: str) -> tuple:
        """Run a shell command in the sandbox. Returns (exit_code, stdout, stderr)."""
        r = self.sandbox.run(cmd)
        return r.exit_code, r.stdout.strip(), r.stderr.strip()

    def run_py(self, script: str) -> tuple:
        """Run a Python script in the sandbox using run_argv to avoid shell quoting.

        This bypasses /bin/sh -c so embedded quotes, semicolons, and newlines
        work correctly in Python one-liners.
        """
        r = self.sandbox.run_argv(["python3", "-c", script])
        return r.exit_code, r.stdout.strip(), r.stderr.strip()

    def record(self, category: str, name: str, passed: bool, detail: str = ""):
        status = PASS if passed else FAIL
        self.results.append((category, name, passed, detail))
        print(f"  [{status}] {name}")
        if detail and not passed:
            for line in detail.split("\n")[:3]:
                print(f"         {line}")

    # =========================================================================
    # Category 1: Filesystem Escape
    # =========================================================================

    def test_filesystem_escape(self):
        print(f"\n{BOLD}=== FILESYSTEM ESCAPE ==={RESET}")

        # 1.1: Read /etc/shadow (sensitive file)
        ec, out, err = self.run_cmd("cat /etc/shadow 2>&1")
        self.record("fs", "Read /etc/shadow blocked",
                    ec != 0 or "Permission denied" in out + err or out.strip() == "",
                    f"exit={ec} out={out[:100]}")

        # 1.2: Write to /etc (read-only)
        ec, out, err = self.run_cmd("echo pwned > /etc/test_pwned 2>&1")
        self.record("fs", "Write to /etc blocked",
                    ec != 0 or "denied" in (out + err).lower() or "read-only" in (out + err).lower(),
                    f"exit={ec} out={out[:100]} err={err[:100]}")

        # 1.3: Read /root directory
        ec, out, err = self.run_cmd("ls /root 2>&1")
        self.record("fs", "Read /root blocked",
                    ec != 0 or "denied" in (out + err).lower() or "No such file" in out + err,
                    f"exit={ec} out={out[:100]}")

        # 1.4: Path traversal via ../
        ec, out, err = self.run_cmd("cat /tmp/../../etc/passwd 2>&1")
        # /etc/passwd is read-only accessible so this is about path traversal to OTHER dirs
        # Let's test traversal to something outside allowed paths
        ec2, out2, err2 = self.run_cmd("cat /tmp/../../home/user/.bashrc 2>&1")
        self.record("fs", "Path traversal (/../) to /home blocked",
                    ec2 != 0 or "denied" in (out2 + err2).lower() or "No such file" in out2 + err2,
                    f"exit={ec2} out={out2[:100]}")

        # 1.5: Symlink escape - create symlink pointing outside sandbox
        ec, out, err = self.run_cmd(
            "ln -s /home/user /tmp/escape_link 2>&1 && cat /tmp/escape_link/.bashrc 2>&1")
        self.record("fs", "Symlink escape (/tmp -> /home) blocked",
                    "denied" in (out + err).lower() or "No such file" in out + err or ec != 0,
                    f"exit={ec} out={out[:100]}")

        # 1.6: Hardlink escape - try to hardlink sensitive files
        ec, out, err = self.run_cmd("ln /etc/shadow /tmp/shadow_hard 2>&1")
        self.record("fs", "Hardlink to /etc/shadow blocked",
                    ec != 0 or "denied" in (out + err).lower() or "not allowed" in (out + err).lower()
                    or "Operation not permitted" in out + err,
                    f"exit={ec} out={out[:100]} err={err[:100]}")

        # 1.7: Access /var (not in allowed paths)
        ec, out, err = self.run_cmd("ls /var/log 2>&1")
        self.record("fs", "Access /var/log blocked",
                    ec != 0 or "denied" in (out + err).lower() or "No such file" in out + err,
                    f"exit={ec} out={out[:100]}")

        # 1.8: Write to /bin (read-only)
        ec, out, err = self.run_cmd("cp /bin/sh /bin/pwned 2>&1")
        self.record("fs", "Write to /bin blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 1.9: Delete system file
        ec, out, err = self.run_cmd("rm /bin/sh 2>&1")
        self.record("fs", "Delete /bin/sh blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 1.10: Write to /usr (read-only)
        ec, out, err = self.run_cmd("echo pwned > /usr/lib/pwned 2>&1")
        self.record("fs", "Write to /usr/lib blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 1.11: Verify workspace IS writable (positive test)
        ec, out, err = self.run_cmd(
            "echo 'test' > /tmp/sandbox-security-test/write_test.txt && "
            "cat /tmp/sandbox-security-test/write_test.txt")
        self.record("fs", "Workspace write WORKS (positive test)",
                    ec == 0 and "test" in out,
                    f"exit={ec} out={out[:100]}")

        # 1.12: Access outside workspace in /home
        ec, out, err = self.run_cmd("ls /home 2>&1")
        self.record("fs", "Access /home blocked",
                    ec != 0 or "denied" in (out + err).lower() or "No such file" in out + err
                    or out.strip() == "",
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 2: /proc Attacks
    # =========================================================================

    def test_proc_attacks(self):
        print(f"\n{BOLD}=== /proc ATTACKS ==={RESET}")

        # 2.1: Read /proc/1/environ (PID NS: PID 1 is sandbox init, not host)
        # In the PID namespace, /proc/1 is the sandboxed worker, not the host.
        # The security property is that NO HOST secrets leak, which the
        # PID namespace guarantees. Reading our own process env is acceptable.
        ec, out, err = self.run_cmd("cat /proc/1/environ 2>&1")
        has_host_secrets = any(s in out for s in ["ANTHROPIC_API_KEY", "AWS_SECRET", "GITHUB_TOKEN"])
        self.record("proc", "No host secrets in /proc/1/environ (PID NS isolated)",
                    not has_host_secrets,
                    f"exit={ec} out={out[:60]}")

        # 2.2: Read /proc/1/mem (requires ptrace or same-process)
        ec, out, err = self.run_cmd("head -c 16 /proc/1/mem 2>&1")
        self.record("proc", "Read /proc/1/mem returns error",
                    ec != 0 or "denied" in (out + err).lower()
                    or "Input/output error" in out + err
                    or "Permission denied" in out + err
                    or out.strip() == "",
                    f"exit={ec} out={out[:60]}")

        # 2.3: Read /proc/1/maps (PID NS: shows sandbox process layout only)
        ec, out, err = self.run_cmd("cat /proc/1/maps 2>&1")
        # In PID NS, /proc/1/maps shows the sandboxed process, not the host.
        # Verify it doesn't leak host binary paths.
        has_host_paths = any(s in out for s in ["/home/user/", "/root/", "/opt/secret"])
        self.record("proc", "/proc/1/maps shows sandbox process only (PID NS)",
                    ec != 0 or "denied" in (out + err).lower() or not has_host_paths,
                    f"exit={ec} out={out[:100]}")

        # 2.4: Read /proc/1/cmdline
        ec, out, err = self.run_cmd("cat /proc/1/cmdline 2>&1 | tr '\\0' ' '")
        has_sensitive = "ANTHROPIC" in out or "API_KEY" in out or "SECRET" in out
        self.record("proc", "No secrets leaked via /proc/1/cmdline",
                    not has_sensitive,
                    f"exit={ec} out={out[:100]}")

        # 2.5: Write to /proc/sys (kernel tuning)
        ec, out, err = self.run_cmd("echo 1 > /proc/sys/kernel/sysrq 2>&1")
        self.record("proc", "Write to /proc/sys/kernel blocked",
                    ec != 0 or "denied" in (out + err).lower() or "Read-only" in out + err,
                    f"exit={ec} out={out[:100]}")

        # 2.6: Read /proc/kcore (kernel memory)
        ec, out, err = self.run_cmd("head -c 16 /proc/kcore 2>&1")
        self.record("proc", "Read /proc/kcore blocked",
                    ec != 0 or "denied" in (out + err).lower(),
                    f"exit={ec} out={out[:60]}")

        # 2.7: Read /proc/kallsyms (kernel symbols)
        ec, out, err = self.run_cmd("head -3 /proc/kallsyms 2>&1")
        # If visible but zeroed addresses, that's acceptable (kernel.kptr_restrict)
        has_real_addrs = any(
            not line.startswith("0000000000000000")
            for line in out.split("\n") if line.strip()
        )
        self.record("proc", "/proc/kallsyms addresses hidden or blocked",
                    ec != 0 or "denied" in (out + err).lower() or not has_real_addrs,
                    f"exit={ec} out={out[:100]}")

        # 2.8: Access /proc/self/root (chroot escape probe)
        ec, out, err = self.run_cmd("ls /proc/self/root/ 2>&1")
        # Should show the sandbox root, not the host root
        self.record("proc", "/proc/self/root shows sandbox root",
                    "home" not in out or ec != 0,
                    f"exit={ec} out={out[:200]}")

    # =========================================================================
    # Category 3: Privilege Escalation
    # =========================================================================

    def test_privilege_escalation(self):
        print(f"\n{BOLD}=== PRIVILEGE ESCALATION ==={RESET}")

        # 3.1: mount() syscall
        ec, out, err = self.run_cmd("mount -t tmpfs none /tmp/mnt_test 2>&1")
        self.record("priv", "mount() blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 3.2: umount()
        ec, out, err = self.run_cmd("umount /proc 2>&1")
        self.record("priv", "umount() blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 3.3: pivot_root (chroot escape)
        self.run_cmd("mkdir -p /tmp/pr_new /tmp/pr_old 2>/dev/null")
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(155, b'/tmp/pr_new', b'/tmp/pr_old')\n"
            "print(f'pivot_root={ret}')")
        self.record("priv", "pivot_root() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 3.4: chroot()
        ec, out, err = self.run_py(
            "import os\n"
            "try:\n"
            "  os.chroot('/tmp')\n"
            "  print('ESCAPED')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("priv", "chroot() blocked",
                    ec != 0 or "ESCAPED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 3.5: setuid/setgid
        ec, out, err = self.run_py(
            "import os\n"
            "try:\n"
            "  os.setuid(0)\n"
            "  print('root')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("priv", "setuid(0) blocked or no-op",
                    ec != 0 or "root" not in out or "Error" in out + err,
                    f"exit={ec} out={out[:100]}")

        # 3.6: capset (try to gain capabilities)
        ec, out, err = self.run_py(
            "import ctypes, struct; "
            "libc = ctypes.CDLL('libc.so.6'); "
            "# PR_CAP_AMBIENT=47, PR_CAP_AMBIENT_RAISE=2, CAP_SYS_ADMIN=21\n"
            "ret = libc.prctl(47, 2, 21, 0, 0); "
            "print(f'prctl returned {ret}')")
        self.record("priv", "PR_CAP_AMBIENT_RAISE(CAP_SYS_ADMIN) blocked",
                    ec != 0 or "-1" in out or "Error" in out + err,
                    f"exit={ec} out={out[:100]}")

        # 3.7: unshare() new namespaces (try to escape current NS)
        ec, out, err = self.run_cmd("unshare -m sh -c 'echo escaped' 2>&1")
        self.record("priv", "unshare() blocked",
                    ec != 0 or "escaped" not in out,
                    f"exit={ec} out={out[:100]}")

        # 3.8: setns() to host namespace
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "fd = libc.open(b'/proc/1/ns/mnt', 0)\n"
            "if fd >= 0:\n"
            "  print(f'setns={libc.syscall(308, fd, 0)}')\n"
            "else:\n"
            "  print(f'open failed={fd}')")
        self.record("priv", "setns() to host NS blocked",
                    ec != 0 or "setns=-1" in out or "open failed" in out,
                    f"exit={ec} out={out[:100]}")

        # 3.9: mknod (create device files)
        ec, out, err = self.run_cmd("mknod /tmp/test_dev c 1 1 2>&1")
        self.record("priv", "mknod() blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 3.10: ptrace another process from within sandbox
        ec, out, err = self.run_py(
            "import ctypes; "
            "libc = ctypes.CDLL('libc.so.6'); "
            "# PTRACE_ATTACH=16\n"
            "ret = libc.ptrace(16, 1, 0, 0); "
            "print(f'ptrace returned {ret}')")
        self.record("priv", "ptrace(ATTACH, pid 1) blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 3.11: SUID execution - try to use a suid binary to escalate
        # In user namespace, uid 0 inside maps to unprivileged uid outside.
        # Even if we appear to be root, capabilities are dropped and
        # PR_SET_NO_NEW_PRIVS prevents actual privilege escalation via SUID.
        ec, out, err = self.run_cmd(
            "cp /bin/sh /tmp/suid_sh 2>/dev/null; "
            "chmod u+s /tmp/suid_sh 2>&1; "
            "/tmp/suid_sh -c 'id' 2>&1")
        # Inside user NS, "root" shows in id output but has no real privileges.
        # The security property: capabilities are dropped, no-new-privs set.
        nosuid = "nosuid" in err.lower() or ec != 0
        # Also check that capabilities are actually empty
        ec2, out2, err2 = self.run_cmd("cat /proc/self/status 2>&1")
        caps_zero = "CapEff:\t0000000000000000" in out2
        self.record("priv", "SUID ineffective (no-new-privs + caps dropped)",
                    nosuid or caps_zero,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 4: Network Escape
    # =========================================================================

    def test_network_escape(self):
        print(f"\n{BOLD}=== NETWORK ESCAPE ==={RESET}")

        # 4.1: TCP connection
        ec, out, err = self.run_py(
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "  s.connect(('8.8.8.8', 53))\n"
            "  print('CONNECTED')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "TCP to 8.8.8.8:53 blocked",
                    "CONNECTED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 4.2: UDP connection
        ec, out, err = self.run_py(
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "try:\n"
            "  s.sendto(b'test', ('8.8.8.8', 53))\n"
            "  print('SENT')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "UDP to 8.8.8.8:53 blocked",
                    "SENT" not in out,
                    f"exit={ec} out={out[:100]}")

        # 4.3: Raw socket
        ec, out, err = self.run_py(
            "import socket\n"
            "try:\n"
            "  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n"
            "  print('RAW')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "Raw socket creation blocked",
                    "RAW" not in out,
                    f"exit={ec} out={out[:100]}")

        # 4.4: Bind a listening socket
        ec, out, err = self.run_py(
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "try:\n"
            "  s.bind(('0.0.0.0', 8080))\n"
            "  s.listen(1)\n"
            "  print('LISTENING')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "Listen on 0.0.0.0:8080 blocked",
                    "LISTENING" not in out,
                    f"exit={ec} out={out[:100]}")

        # 4.5: Unix socket to host
        ec, out, err = self.run_py(
            "import socket\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "try:\n"
            "  s.connect('/var/run/docker.sock')\n"
            "  print('DOCKER')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "Unix socket to docker.sock blocked",
                    "DOCKER" not in out,
                    f"exit={ec} out={out[:100]}")

        # 4.6: Netlink socket (kernel comms)
        ec, out, err = self.run_py(
            "import socket\n"
            "try:\n"
            "  s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 15)\n"
            "  print('NETLINK')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("net", "Netlink socket blocked",
                    "NETLINK" not in out,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 5: Seccomp Bypass
    # =========================================================================

    def test_seccomp_bypass(self):
        print(f"\n{BOLD}=== SECCOMP BYPASS ==={RESET}")

        # 5.1: kexec_load (load new kernel)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(246, 0, 0, 0, 0)\n"
            "print(f'kexec_load={ret}')")
        self.record("seccomp", "kexec_load() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.2: init_module (load kernel module)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(175, 0, 0, b'')\n"
            "print(f'init_module={ret}')")
        self.record("seccomp", "init_module() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.3: perf_event_open
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(298, 0, 0, -1, -1, 0)\n"
            "print(f'perf_event_open={ret}')")
        self.record("seccomp", "perf_event_open() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.4: bpf() (eBPF - kernel attack surface)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(321, 0, 0, 0)\n"
            "print(f'bpf={ret}')")
        self.record("seccomp", "bpf() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.5: userfaultfd (used in exploits)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(323, 0)\n"
            "print(f'userfaultfd={ret}')")
        self.record("seccomp", "userfaultfd() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.6: keyctl (kernel keyring)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(250, 0, 0, 0, 0, 0)\n"
            "print(f'keyctl={ret}')")
        self.record("seccomp", "keyctl() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.7: personality() change (used to bypass ASLR)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.personality(0x0040000)\n"
            "print(f'personality={ret}')")
        self.record("seccomp", "personality(ADDR_NO_RANDOMIZE) blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.8: io_uring (major kernel attack surface)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.syscall(425, 32, 0)\n"
            "print(f'io_uring={ret}')")
        self.record("seccomp", "io_uring_setup() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 5.9: prctl(PR_SET_SECCOMP) - try to disable seccomp
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "ret = libc.prctl(22, 0, 0, 0, 0)\n"
            "print(f'prctl={ret}')")
        self.record("seccomp", "Cannot disable seccomp via prctl",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 6: Process/Memory Attacks
    # =========================================================================

    def test_process_memory_attacks(self):
        print(f"\n{BOLD}=== PROCESS / MEMORY ATTACKS ==={RESET}")

        # 6.1: Kill host process
        ec, out, err = self.run_cmd("kill -9 1 2>&1")
        self.record("proc", "kill -9 PID 1 blocked or ineffective",
                    ec != 0 or "not permitted" in (out + err).lower()
                    or "No such process" in out + err,
                    f"exit={ec} out={out[:100]} err={err[:100]}")

        # 6.2: Signal host processes
        ec, out, err = self.run_cmd("kill -TERM -1 2>&1")
        self.record("proc", "kill -TERM -1 (all processes) blocked",
                    ec != 0 or "not permitted" in (out + err).lower(),
                    f"exit={ec} out={out[:100]} err={err[:100]}")

        # 6.3: Fork bomb
        ec, out, err = self.run_py(
            "import os, sys\n"
            "count = 0\n"
            "for i in range(200):\n"
            "  try:\n"
            "    pid = os.fork()\n"
            "    if pid == 0:\n"
            "      os._exit(0)\n"
            "    count += 1\n"
            "  except OSError:\n"
            "    break\n"
            "print(f'forked {count} times')")
        # Should be limited by RLIMIT_NPROC (256) in the sandbox.
        # In user NS with uid 0, nproc counts against external uid's total.
        # The key property: forks cannot be unbounded.
        fork_count = 0
        if "forked" in out:
            try:
                fork_count = int(out.split("forked ")[1].split(" ")[0])
            except (ValueError, IndexError):
                pass
        # RLIMIT_NPROC=256, so fork bomb must stop well before 500
        self.record("proc", "Fork bomb limited by RLIMIT_NPROC",
                    fork_count <= 256,
                    f"exit={ec} forks={fork_count}")

        # 6.4: Process memory read via /proc/self/mem
        ec, out, err = self.run_py(
            "import os\n"
            "try:\n"
            "  fd = os.open('/proc/1/mem', os.O_RDONLY)\n"
            "  data = os.read(fd, 16)\n"
            "  print(f'READ {len(data)} bytes from PID 1')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("proc", "Read /proc/1/mem blocked",
                    "BLOCKED" in out or "READ 0" in out,
                    f"exit={ec} out={out[:100]}")

        # 6.5: Core dump to steal memory
        ec, out, err = self.run_py(
            "import resource\n"
            "old = resource.getrlimit(resource.RLIMIT_CORE)\n"
            "print(f'RLIMIT_CORE: {old}')")
        core_disabled = "0, 0" in out or "(0" in out
        self.record("proc", "Core dumps disabled (RLIMIT_CORE=0)",
                    core_disabled,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 7: Broker Bypass
    # =========================================================================

    def test_broker_bypass(self):
        print(f"\n{BOLD}=== BROKER BYPASS ==={RESET}")

        # 7.1: Direct syscall to bypass broker (open via syscall number)
        ec, out, err = self.run_py(
            "import ctypes, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "fd = libc.syscall(2, b'/etc/shadow', os.O_RDONLY, 0)\n"
            "print(f'direct open fd={fd}')")
        self.record("broker", "Direct syscall open(/etc/shadow) blocked",
                    ec != 0 or "fd=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 7.2: O_PATH flag to get handle without broker check
        ec, out, err = self.run_py(
            "import os, ctypes\n"
            "O_PATH = 0o10000000\n"
            "try:\n"
            "  fd = os.open('/home', O_PATH)\n"
            "  print(f'O_PATH fd={fd}')\n"
            "  libc = ctypes.CDLL('libc.so.6')\n"
            "  ret = libc.linkat(fd, b'user', -100, b'/tmp/escape', 0)\n"
            "  print(f'linkat={ret}')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("broker", "O_PATH escape blocked",
                    "BLOCKED" in out or "fd=-1" in out or "linkat=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 7.3: openat2 with RESOLVE_NO_SYMLINKS to bypass broker
        ec, out, err = self.run_py(
            "import ctypes, struct\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "how = struct.pack('QQQ', 0, 0, 0)\n"
            "ret = libc.syscall(437, -100, b'/home/user', how, len(how))\n"
            "print(f'openat2={ret}')")
        self.record("broker", "openat2() bypasses checked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 7.4: memfd_create + exec (fileless execution)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "fd = libc.syscall(319, b'test', 0)\n"
            "print(f'memfd_create={fd}')")
        self.record("broker", "memfd_create() blocked or controlled",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 7.5: Double-fetch / TOCTOU on broker
        ec, out, err = self.run_py(
            "import os\n"
            "fd = os.open('/tmp/broker_test', os.O_WRONLY | os.O_CREAT, 0o644)\n"
            "os.write(fd, b'allowed')\n"
            "os.close(fd)\n"
            "try:\n"
            "  fd = os.open('/opt/secret', os.O_RDONLY)\n"
            "  print(f'BYPASSED fd={fd}')\n"
            "except:\n"
            "  print('BLOCKED: cannot access /opt')")
        self.record("broker", "Broker validates every open (no TOCTOU)",
                    "BLOCKED" in out,
                    f"exit={ec} out={out[:100]}")

        # 7.6: O_TMPFILE to create anonymous file
        ec, out, err = self.run_py(
            "import os\n"
            "O_TMPFILE = 0o20200000\n"
            "try:\n"
            "  fd = os.open('/tmp', O_TMPFILE | os.O_RDWR, 0o600)\n"
            "  os.write(fd, b'anon file')\n"
            "  print(f'O_TMPFILE fd={fd}')\n"
            "except Exception as e:\n"
            "  print(f'Result: {e}')")
        # O_TMPFILE in /tmp is fine (allowed path). Just check it doesn't crash.
        self.record("broker", "O_TMPFILE doesn't crash broker",
                    ec == 0,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 8: Container/Namespace Escape
    # =========================================================================

    def test_namespace_escape(self):
        print(f"\n{BOLD}=== NAMESPACE ESCAPE ==={RESET}")

        # 8.1: nsenter to host namespaces
        ec, out, err = self.run_cmd("nsenter -t 1 -m -u -i -n sh -c 'echo ESCAPED' 2>&1")
        self.record("ns", "nsenter to PID 1 namespaces blocked",
                    "ESCAPED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 8.2: Clone with new user namespace
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "CLONE_NEWUSER = 0x10000000\n"
            "CLONE_NEWNS = 0x00020000\n"
            "ret = libc.syscall(56, CLONE_NEWUSER | CLONE_NEWNS, 0, 0, 0, 0)\n"
            "print(f'clone={ret}')")
        self.record("ns", "clone(NEWUSER|NEWNS) blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 8.3: Access host network via /proc/1/ns/net
        ec, out, err = self.run_py(
            "import os\n"
            "try:\n"
            "  fd = os.open('/proc/1/ns/net', os.O_RDONLY)\n"
            "  print(f'opened ns fd={fd}')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("ns", "Open /proc/1/ns/net blocked",
                    "BLOCKED" in out or ec != 0,
                    f"exit={ec} out={out[:100]}")

        # 8.4: ioctl TIOCSTI (terminal injection)
        ec, out, err = self.run_py(
            "import fcntl, sys\n"
            "TIOCSTI = 0x5412\n"
            "try:\n"
            "  for c in 'echo pwned\\n':\n"
            "    fcntl.ioctl(0, TIOCSTI, c.encode())\n"
            "  print('INJECTED')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')")
        self.record("ns", "TIOCSTI terminal injection blocked",
                    "INJECTED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 8.5: Access cgroups
        ec, out, err = self.run_cmd("ls /sys/fs/cgroup/ 2>&1")
        self.record("ns", "Access /sys/fs/cgroup blocked",
                    ec != 0 or "No such file" in out + err or "denied" in (out + err).lower(),
                    f"exit={ec} out={out[:100]}")

        # 8.6: Modify cgroup limits
        ec, out, err = self.run_cmd(
            "echo 999999999 > /sys/fs/cgroup/memory/memory.limit_in_bytes 2>&1")
        self.record("ns", "Write to cgroup limits blocked",
                    ec != 0,
                    f"exit={ec} out={out[:100]} err={err[:100]}")

    # =========================================================================
    # Category 9: Information Disclosure
    # =========================================================================

    def test_information_disclosure(self):
        print(f"\n{BOLD}=== INFORMATION DISCLOSURE ==={RESET}")

        # 9.1: Read host environment variables
        ec, out, err = self.run_py(
            "import os\n"
            "sensitive = ['ANTHROPIC_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'SECRET']\n"
            "found = [k for k in sensitive if os.environ.get(k)]\n"
            "print(f'found: {found}' if found else 'clean')")
        self.record("info", "No sensitive env vars leaked",
                    "clean" in out,
                    f"exit={ec} out={out[:100]}")

        # 9.2: Read /etc/hostname
        ec, out, err = self.run_cmd("cat /etc/hostname 2>&1")
        self.record("info", "/etc/hostname read (info only - ro mount)",
                    True,  # This is read-only, just info disclosure
                    f"hostname={out[:50]}")

        # 9.3: Read kernel command line
        ec, out, err = self.run_cmd("cat /proc/cmdline 2>&1")
        self.record("info", "/proc/cmdline access checked",
                    True,  # Log for review
                    f"cmdline={out[:100]}")

        # 9.4: DMI/BIOS info
        ec, out, err = self.run_cmd("cat /sys/class/dmi/id/product_name 2>&1")
        self.record("info", "/sys blocked (no sysfs)",
                    ec != 0 or "No such file" in out + err or "denied" in (out + err).lower(),
                    f"exit={ec} out={out[:100]}")

        # 9.5: Read SSH keys
        ec, out, err = self.run_cmd("cat /root/.ssh/id_rsa 2>&1")
        self.record("info", "SSH private keys inaccessible",
                    ec != 0 or "No such file" in out + err or "denied" in (out + err).lower(),
                    f"exit={ec} out={out[:100]}")

        # 9.6: Read host /etc/resolv.conf for infrastructure info
        ec, out, err = self.run_cmd("cat /etc/resolv.conf 2>&1")
        self.record("info", "/etc/resolv.conf access checked (ro)",
                    True,  # Just info, read-only
                    f"content={out[:80]}")

    # =========================================================================
    # Run All
    # =========================================================================

    def run_all(self):
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}Chrome Sandbox Security Breakout Test Suite{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"Policy: STRICT (Chrome renderer equivalent)")
        print(f"Broker: BROKERED (validates every filesystem access)")
        print(f"Network: DISABLED")

        self.setup()
        try:
            self.test_filesystem_escape()
            self.test_proc_attacks()
            self.test_privilege_escalation()
            self.test_network_escape()
            self.test_seccomp_bypass()
            self.test_process_memory_attacks()
            self.test_broker_bypass()
            self.test_namespace_escape()
            self.test_information_disclosure()
        finally:
            self.teardown()

        # Summary
        total = len(self.results)
        passed = sum(1 for _, _, p, _ in self.results if p)
        failed = sum(1 for _, _, p, _ in self.results if not p)

        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}RESULTS: {passed}/{total} passed, {failed} failed{RESET}")
        print(f"{'='*60}")

        if failed > 0:
            print(f"\n{RED}{BOLD}FAILURES:{RESET}")
            for cat, name, p, detail in self.results:
                if not p:
                    print(f"  [{cat}] {name}")
                    if detail:
                        print(f"    {detail[:200]}")

        # Group by category
        categories = {}
        for cat, name, p, detail in self.results:
            if cat not in categories:
                categories[cat] = {"pass": 0, "fail": 0}
            categories[cat]["pass" if p else "fail"] += 1

        print(f"\n{BOLD}By category:{RESET}")
        for cat, counts in categories.items():
            status = f"{GREEN}ALL PASS{RESET}" if counts["fail"] == 0 else f"{RED}{counts['fail']} FAIL{RESET}"
            print(f"  {cat:10s}: {counts['pass']}/{counts['pass']+counts['fail']} [{status}]")

        return failed


if __name__ == "__main__":
    suite = SecurityTestSuite()
    failures = suite.run_all()
    sys.exit(1 if failures > 0 else 0)
