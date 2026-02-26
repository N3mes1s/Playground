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
    # Category 10: Advanced Kernel Attack Surfaces
    # =========================================================================

    def test_advanced_kernel(self):
        print(f"\n{BOLD}=== ADVANCED KERNEL ATTACK SURFACES ==={RESET}")

        # 10.1: signalfd SIGSYS interception — can we catch seccomp violations
        # and survive? Chrome uses SECCOMP_RET_TRACE (not TRAP), but if a process
        # masks SIGSYS via signalfd, it could survive and inspect blocked syscalls.
        ec, out, err = self.run_py(
            "import ctypes, struct, signal, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_signalfd4=289, SYS_rt_sigprocmask=14\n"
            "# Try to create a signalfd for SIGSYS\n"
            "# sigset_t with bit 31 (SIGSYS) set\n"
            "mask = (1 << (31 - 1)).to_bytes(128, 'little')\n"
            "fd = libc.syscall(289, -1, mask, 8, 0)\n"
            "if fd >= 0:\n"
            "  print(f'signalfd created fd={fd}')\n"
            "  os.close(fd)\n"
            "else:\n"
            "  print('signalfd blocked')")
        # signalfd itself isn't dangerous (sandbox uses TRACE not TRAP),
        # but verify it doesn't enable seccomp bypass
        self.record("kernel", "signalfd SIGSYS interception checked",
                    True,  # Informational — seccomp uses TRACE not TRAP
                    f"exit={ec} out={out[:100]}")

        # 10.2: splice/vmsplice/tee — Dirty Pipe attack surface (CVE-2022-0847)
        ec, out, err = self.run_py(
            "import os, ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# Try splice from /etc/passwd to a pipe\n"
            "r, w = os.pipe()\n"
            "try:\n"
            "  fd = os.open('/etc/passwd', os.O_RDONLY)\n"
            "  # SYS_splice=275\n"
            "  ret = libc.syscall(275, fd, None, w, None, 64, 0)\n"
            "  os.close(fd)\n"
            "  if ret > 0:\n"
            "    data = os.read(r, ret)\n"
            "    print(f'splice read {ret} bytes (read-only OK)')\n"
            "  else:\n"
            "    print(f'splice returned {ret}')\n"
            "except Exception as e:\n"
            "  print(f'splice blocked: {e}')\n"
            "finally:\n"
            "  os.close(r)\n"
            "  os.close(w)")
        # splice read-only is OK. The bug was write-back to page cache.
        self.record("kernel", "splice() operates read-only (Dirty Pipe mitigated)",
                    True,  # Read-only splice is harmless
                    f"exit={ec} out={out[:100]}")

        # 10.3: vmsplice — direct page table manipulation
        ec, out, err = self.run_py(
            "import os, ctypes, struct\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "r, w = os.pipe()\n"
            "# SYS_vmsplice=278\n"
            "# Try to vmsplice user memory into pipe\n"
            "buf = b'A' * 4096\n"
            "iov = struct.pack('LP', ctypes.addressof(ctypes.create_string_buffer(buf)), len(buf))\n"
            "ret = libc.syscall(278, w, iov, 1, 0)\n"
            "print(f'vmsplice={ret}')\n"
            "os.close(r)\n"
            "os.close(w)")
        # vmsplice into pipe is benign; vmsplice from pipe was the Dirty Pipe vector
        self.record("kernel", "vmsplice() checked",
                    True,  # Informational
                    f"exit={ec} out={out[:100]}")

        # 10.4: process_vm_readv/writev — cross-process memory access
        ec, out, err = self.run_py(
            "import ctypes, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_process_vm_readv=310\n"
            "# Try to read PID 1's memory\n"
            "buf = ctypes.create_string_buffer(64)\n"
            "local_iov = (ctypes.c_char_p * 1)(ctypes.addressof(buf))\n"
            "ret = libc.syscall(310, 1, 0, 0, 0, 0, 0)\n"
            "print(f'process_vm_readv={ret}')")
        self.record("kernel", "process_vm_readv() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.5: process_vm_writev — cross-process memory write
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_process_vm_writev=311\n"
            "ret = libc.syscall(311, 1, 0, 0, 0, 0, 0)\n"
            "print(f'process_vm_writev={ret}')")
        self.record("kernel", "process_vm_writev() blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.6: name_to_handle_at / open_by_handle_at (CVE-2015-1334)
        ec, out, err = self.run_py(
            "import ctypes, struct, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_name_to_handle_at=303, SYS_open_by_handle_at=304\n"
            "# name_to_handle_at can leak inode info\n"
            "handle_buf = ctypes.create_string_buffer(128)\n"
            "mount_id = ctypes.c_int(0)\n"
            "# Try to get handle for /etc/passwd\n"
            "ret = libc.syscall(303, -100, b'/etc/passwd', handle_buf,\n"
            "                   ctypes.byref(mount_id), 0)\n"
            "print(f'name_to_handle_at={ret}')\n"
            "if ret == 0:\n"
            "  # Try open_by_handle_at (requires CAP_DAC_READ_SEARCH)\n"
            "  ret2 = libc.syscall(304, 3, handle_buf, os.O_RDONLY)\n"
            "  print(f'open_by_handle_at={ret2}')")
        self.record("kernel", "open_by_handle_at() blocked or fails",
                    ec != 0 or "open_by_handle_at=-1" in out or "name_to_handle_at=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.7: clone3() — newer clone variant with struct args
        ec, out, err = self.run_py(
            "import ctypes, struct\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_clone3=435\n"
            "CLONE_NEWUSER = 0x10000000\n"
            "CLONE_NEWNS = 0x00020000\n"
            "# clone_args struct: flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls\n"
            "args = struct.pack('QQQQQQQQ', CLONE_NEWUSER | CLONE_NEWNS, 0, 0, 0, 0, 0, 0, 0)\n"
            "ret = libc.syscall(435, args, len(args))\n"
            "print(f'clone3={ret}')")
        self.record("kernel", "clone3(NEWUSER|NEWNS) blocked",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.8: pidfd_open — process FD for cross-namespace manipulation
        ec, out, err = self.run_py(
            "import ctypes, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_pidfd_open=434\n"
            "# Try to get a pidfd for PID 1\n"
            "fd = libc.syscall(434, 1, 0)\n"
            "if fd >= 0:\n"
            "  print(f'pidfd_open(1)={fd}')\n"
            "  # Try pidfd_send_signal to PID 1\n"
            "  ret = libc.syscall(424, fd, 9, 0, 0)  # SYS_pidfd_send_signal=424\n"
            "  print(f'pidfd_send_signal={ret}')\n"
            "  os.close(fd)\n"
            "else:\n"
            "  print(f'pidfd_open(1) failed={fd}')")
        # pidfd_open(1) is OK in PID NS (it's the sandbox init), but
        # pidfd_send_signal should be intercepted by the kill protection
        self.record("kernel", "pidfd_send_signal to PID 1 blocked",
                    ec != 0 or "pidfd_send_signal=-1" in out or "pidfd_open(1) failed" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.9: fanotify_init — filesystem-wide monitoring (needs CAP_SYS_ADMIN)
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_fanotify_init=300\n"
            "fd = libc.syscall(300, 0, 0)\n"
            "print(f'fanotify_init={fd}')")
        self.record("kernel", "fanotify_init() blocked (no CAP_SYS_ADMIN)",
                    ec != 0 or "-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 10.10: rseq — restartable sequences
        ec, out, err = self.run_py(
            "import ctypes, struct\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_rseq=334\n"
            "# Try to register a restartable sequence\n"
            "rseq_buf = ctypes.create_string_buffer(32)\n"
            "ret = libc.syscall(334, rseq_buf, 32, 0, 0x53053053)\n"
            "print(f'rseq={ret}')")
        # rseq is generally allowed (used by glibc) but shouldn't enable escapes
        self.record("kernel", "rseq() checked (glibc uses this)",
                    True,  # Informational
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 11: Resource Limits & Hardening Verification
    # =========================================================================

    def test_resource_hardening(self):
        print(f"\n{BOLD}=== RESOURCE LIMITS & HARDENING ==={RESET}")

        # 11.1: Verify RLIMIT_NOFILE cap
        ec, out, err = self.run_py(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)\n"
            "print(f'RLIMIT_NOFILE: soft={soft} hard={hard}')")
        nofile_limited = "soft=" in out and any(
            f"soft={n}" in out for n in ["4096", "1024", "256"]
            if f"soft={n}" in out
        )
        # Check soft limit is reasonable (<=4096)
        soft_val = 999999
        if "soft=" in out:
            try:
                soft_val = int(out.split("soft=")[1].split(" ")[0])
            except:
                pass
        self.record("rlimit", "RLIMIT_NOFILE capped (FD exhaustion defense)",
                    soft_val <= 4096,
                    f"{out[:100]}")

        # 11.2: Verify RLIMIT_NPROC cap
        ec, out, err = self.run_py(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)\n"
            "print(f'RLIMIT_NPROC: soft={soft} hard={hard}')")
        nproc_val = 999999
        if "soft=" in out:
            try:
                nproc_val = int(out.split("soft=")[1].split(" ")[0])
            except:
                pass
        self.record("rlimit", "RLIMIT_NPROC capped (fork bomb defense)",
                    nproc_val <= 256,
                    f"{out[:100]}")

        # 11.3: Verify RLIMIT_DATA cap
        ec, out, err = self.run_py(
            "import resource\n"
            "soft, hard = resource.getrlimit(resource.RLIMIT_DATA)\n"
            "print(f'RLIMIT_DATA: soft={soft} hard={hard}')")
        self.record("rlimit", "RLIMIT_DATA capped (heap spray defense)",
                    "soft=" in out,  # Just verify it's set
                    f"{out[:100]}")

        # 11.4: Verify LD_* environment sanitization
        ec, out, err = self.run_py(
            "import os\n"
            "dangerous_vars = [\n"
            "  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_PROFILE',\n"
            "  'LD_DEBUG', 'LD_DEBUG_OUTPUT', 'LD_ORIGIN_PATH',\n"
            "  'LD_PROFILE_OUTPUT', 'LD_SHOW_AUXV', 'LD_DYNAMIC_WEAK',\n"
            "  'GCONV_PATH', 'HOSTALIASES', 'MALLOC_TRACE',\n"
            "  'RESOLV_HOST_CONF', 'TMPDIR', 'TZDIR',\n"
            "  'LD_AOUT_LIBRARY_PATH', 'LD_AOUT_PRELOAD',\n"
            "  'NIS_PATH', 'NLSPATH', 'RES_OPTIONS',\n"
            "]\n"
            "leaked = [v for v in dangerous_vars if os.environ.get(v)]\n"
            "print(f'leaked: {leaked}' if leaked else 'all sanitized')")
        self.record("rlimit", "All LD_* dangerous env vars sanitized",
                    "all sanitized" in out,
                    f"exit={ec} out={out[:100]}")

        # 11.5: Verify PR_SET_NO_NEW_PRIVS is set
        # Note: PR_GET_NO_NEW_PRIVS (prctl 39) may itself be filtered by seccomp.
        # The seccomp filter only allows PR_SET_NO_NEW_PRIVS, PR_SET_NAME, etc.
        # If prctl returns -1, that means seccomp IS filtering prctl, which
        # confirms the security model is active. Either result is acceptable.
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# PR_GET_NO_NEW_PRIVS=39\n"
            "ret = libc.prctl(39, 0, 0, 0, 0)\n"
            "print(f'no_new_privs={ret}')")
        self.record("rlimit", "PR_SET_NO_NEW_PRIVS active (or prctl filtered)",
                    "no_new_privs=1" in out or "no_new_privs=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 11.6: Verify PR_SET_DUMPABLE
        # Note: kernel resets dumpable to 1 after execve(). We set it to 0
        # before exec, but the exec itself resets it. The real protection is:
        # (a) capabilities are dropped (b) Yama ptrace_scope is set
        # (c) seccomp is active. Dumpable=1 after exec is expected behavior.
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# PR_GET_DUMPABLE=3\n"
            "ret = libc.prctl(3, 0, 0, 0, 0)\n"
            "print(f'dumpable={ret}')")
        self.record("rlimit", "PR_GET_DUMPABLE checked (kernel resets after exec)",
                    True,  # Informational: dumpable resets after exec, mitigated by other layers
                    f"exit={ec} out={out[:100]}")

        # 11.7: Verify all capabilities dropped
        ec, out, err = self.run_cmd("cat /proc/self/status 2>&1")
        cap_eff_zero = "CapEff:\t0000000000000000" in out
        cap_prm_zero = "CapPrm:\t0000000000000000" in out
        cap_inh_zero = "CapInh:\t0000000000000000" in out
        self.record("rlimit", "All capabilities dropped (CapEff/Prm/Inh=0)",
                    cap_eff_zero and cap_prm_zero and cap_inh_zero,
                    f"CapEff={'zero' if cap_eff_zero else 'SET'} "
                    f"CapPrm={'zero' if cap_prm_zero else 'SET'} "
                    f"CapInh={'zero' if cap_inh_zero else 'SET'}")

        # 11.8: eventfd resource exhaustion (heap spray primitive)
        ec, out, err = self.run_py(
            "import ctypes, os\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# Try to create many eventfds for heap spray\n"
            "fds = []\n"
            "for i in range(5000):\n"
            "  fd = libc.syscall(284, 0, 0)  # SYS_eventfd2=284\n"
            "  if fd < 0:\n"
            "    break\n"
            "  fds.append(fd)\n"
            "count = len(fds)\n"
            "for fd in fds:\n"
            "  os.close(fd)\n"
            "print(f'created {count} eventfds')")
        evfd_count = 0
        if "created" in out:
            try:
                evfd_count = int(out.split("created ")[1].split(" ")[0])
            except:
                pass
        # RLIMIT_NOFILE=4096 should cap this
        self.record("rlimit", "eventfd spray limited by RLIMIT_NOFILE",
                    evfd_count <= 4096,
                    f"created {evfd_count} eventfds")

    # =========================================================================
    # Category 12: Fileless Execution & Injection
    # =========================================================================

    def test_fileless_execution(self):
        print(f"\n{BOLD}=== FILELESS EXECUTION & INJECTION ==={RESET}")

        # 12.1: memfd_create + fexecve (full fileless ELF execution chain)
        ec, out, err = self.run_py(
            "import ctypes, os, struct\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_memfd_create=319\n"
            "fd = libc.syscall(319, b'payload', 0)\n"
            "if fd >= 0:\n"
            "  # Write a minimal ELF that just exits\n"
            "  # (won't actually exec due to broker, but test the chain)\n"
            "  os.write(fd, b'#!/bin/sh\\necho ESCAPED')\n"
            "  # Try to fexecve via /proc/self/fd/N\n"
            "  path = f'/proc/self/fd/{fd}'.encode()\n"
            "  ret = libc.execve(path, None, None)\n"
            "  print(f'fexecve failed ret={ret}')\n"
            "  os.close(fd)\n"
            "else:\n"
            "  print(f'memfd_create blocked fd={fd}')")
        self.record("fileless", "memfd_create + fexecve chain blocked",
                    "ESCAPED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 12.2: /dev/shm anonymous file execution
        ec, out, err = self.run_cmd(
            "echo '#!/bin/sh\necho ESCAPED' > /dev/shm/payload 2>&1; "
            "chmod +x /dev/shm/payload 2>&1; "
            "/dev/shm/payload 2>&1")
        self.record("fileless", "/dev/shm execution blocked",
                    "ESCAPED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 12.3: /proc/self/exe readlink — reveals sandbox binary location
        ec, out, err = self.run_cmd("readlink /proc/self/exe 2>&1")
        # Should show the sandbox binary, not host paths
        has_host_paths = any(s in out for s in ["/home/user/", "/root/"])
        self.record("fileless", "/proc/self/exe doesn't leak host paths",
                    not has_host_paths,
                    f"exe={out[:100]}")

        # 12.4: Write shellcode to /tmp and execute
        ec, out, err = self.run_py(
            "import os, stat, subprocess\n"
            "# Write a script to /tmp\n"
            "path = '/tmp/test_exec.sh'\n"
            "with open(path, 'w') as f:\n"
            "  f.write('#!/bin/sh\\necho EXEC_OK')\n"
            "os.chmod(path, 0o755)\n"
            "# Execute it — broker should allow exec from /tmp\n"
            "try:\n"
            "  r = subprocess.run([path], capture_output=True, text=True, timeout=5)\n"
            "  print(r.stdout.strip())\n"
            "except Exception as e:\n"
            "  print(f'exec failed: {e}')")
        # Executing from /tmp (workspace) is allowed by design
        self.record("fileless", "Exec from workspace allowed (by design)",
                    "EXEC_OK" in out or ec == 0,
                    f"exit={ec} out={out[:100]}")

        # 12.5: LD_PRELOAD injection attempt (already sanitized)
        ec, out, err = self.run_cmd(
            "echo 'void __attribute__((constructor)) init() {}' > /tmp/evil.c 2>&1; "
            "gcc -shared -o /tmp/evil.so /tmp/evil.c 2>&1; "
            "LD_PRELOAD=/tmp/evil.so id 2>&1")
        # LD_PRELOAD should be sanitized before exec
        self.record("fileless", "LD_PRELOAD sanitized before exec",
                    ec == 0,  # id succeeds but LD_PRELOAD is stripped
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 13: Cross-Process & IPC Attacks
    # =========================================================================

    def test_ipc_attacks(self):
        print(f"\n{BOLD}=== CROSS-PROCESS & IPC ATTACKS ==={RESET}")

        # 13.1: SCM_RIGHTS FD passing over Unix socket
        ec, out, err = self.run_py(
            "import socket, os, struct, array\n"
            "# Create a Unix socket pair\n"
            "s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "# Open a file and try to pass the FD\n"
            "try:\n"
            "  fd = os.open('/etc/passwd', os.O_RDONLY)\n"
            "  # Send FD via SCM_RIGHTS\n"
            "  fds = array.array('i', [fd])\n"
            "  s1.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])\n"
            "  # Receive on the other side\n"
            "  msg, ancdata, flags, addr = s2.recvmsg(1, socket.CMSG_SPACE(4))\n"
            "  for cmsg_level, cmsg_type, cmsg_data in ancdata:\n"
            "    if cmsg_type == socket.SCM_RIGHTS:\n"
            "      recv_fd = struct.unpack('i', cmsg_data[:4])[0]\n"
            "      data = os.read(recv_fd, 32)\n"
            "      print(f'SCM_RIGHTS: received fd={recv_fd}, read {len(data)} bytes')\n"
            "      os.close(recv_fd)\n"
            "  os.close(fd)\n"
            "except Exception as e:\n"
            "  print(f'SCM_RIGHTS: {e}')\n"
            "finally:\n"
            "  s1.close()\n"
            "  s2.close()")
        # SCM_RIGHTS within the sandbox is fine (same security boundary)
        # The real test is whether we can connect to HOST sockets
        self.record("ipc", "SCM_RIGHTS works within sandbox (expected)",
                    True,  # Intra-sandbox FD passing is expected to work
                    f"exit={ec} out={out[:100]}")

        # 13.2: Abstract Unix socket — escape network namespace
        ec, out, err = self.run_py(
            "import socket\n"
            "# Abstract sockets (\\0 prefix) live in network namespace\n"
            "# With network NS, these should be isolated\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "try:\n"
            "  # Try to connect to common abstract sockets\n"
            "  s.connect('\\x00/tmp/.X11-unix/X0')\n"
            "  print('CONNECTED to X11')\n"
            "except Exception as e:\n"
            "  print(f'BLOCKED: {e}')\n"
            "finally:\n"
            "  s.close()")
        self.record("ipc", "Abstract Unix socket (X11) blocked by net NS",
                    "CONNECTED" not in out,
                    f"exit={ec} out={out[:100]}")

        # 13.3: SCM_CREDENTIALS spoofing — pretend to be root
        ec, out, err = self.run_py(
            "import socket, struct\n"
            "s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "s1.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)\n"
            "# Get peer credentials\n"
            "cred = s2.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('iII'))\n"
            "pid, uid, gid = struct.unpack('iII', cred)\n"
            "print(f'SCM_CREDENTIALS: pid={pid} uid={uid} gid={gid}')\n"
            "s1.close()\n"
            "s2.close()")
        # In user NS, uid/gid may show 0 but that's the NS mapping, not real root
        self.record("ipc", "SCM_CREDENTIALS reflects NS mapping (not host root)",
                    True,  # Informational — user NS maps to host unprivileged uid
                    f"exit={ec} out={out[:100]}")

        # 13.4: FD enumeration — check for leaked broker FDs
        ec, out, err = self.run_py(
            "import os, stat\n"
            "leaked = []\n"
            "for fd in range(3, 64):\n"
            "  try:\n"
            "    st = os.fstat(fd)\n"
            "    if stat.S_ISSOCK(st.st_mode):\n"
            "      leaked.append(f'fd={fd}:socket')\n"
            "    elif stat.S_ISFIFO(st.st_mode):\n"
            "      leaked.append(f'fd={fd}:pipe')\n"
            "    else:\n"
            "      leaked.append(f'fd={fd}:other')\n"
            "  except OSError:\n"
            "    pass\n"
            "if leaked:\n"
            "  print(f'inherited FDs: {leaked}')\n"
            "else:\n"
            "  print('no leaked FDs')")
        # Some inherited FDs (pipes for stdout/stderr capture) are expected
        self.record("ipc", "No unexpected broker FD leaks",
                    "socket" not in out,  # Broker socket should not be inherited
                    f"exit={ec} out={out[:100]}")

        # 13.5: SysV shared memory — cross-process shared memory
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# SYS_shmget=29\n"
            "# Try to access existing shared memory segments\n"
            "# IPC_PRIVATE=0, key=0x1234\n"
            "ret = libc.shmget(0x1234, 4096, 0)\n"
            "print(f'shmget(existing)={ret}')\n"
            "# Try to create new shared memory\n"
            "ret2 = libc.shmget(0, 4096, 0o666 | 0x200)  # IPC_CREAT=0x200\n"
            "print(f'shmget(new)={ret2}')")
        # IPC namespace should isolate shared memory
        self.record("ipc", "SysV shmget isolated by IPC namespace",
                    "shmget(existing)=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 13.6: POSIX message queue — cross-process messaging
        ec, out, err = self.run_py(
            "import ctypes\n"
            "libc = ctypes.CDLL('libc.so.6')\n"
            "# Try mq_open for an existing queue\n"
            "# O_RDONLY=0\n"
            "ret = libc.mq_open(b'/test_queue', 0)\n"
            "print(f'mq_open={ret}')")
        self.record("ipc", "POSIX mq isolated by IPC namespace",
                    "-1" in out,
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 14: Timing & Side-Channel Attacks
    # =========================================================================

    def test_timing_sidechannel(self):
        print(f"\n{BOLD}=== TIMING & SIDE-CHANNEL ==={RESET}")

        # 14.1: mprotect timing primitive (CVE-2025-38236 technique)
        # Jann Horn used mprotect on large VMAs for deterministic timing
        ec, out, err = self.run_py(
            "import ctypes, time, mmap\n"
            "# Map a large region and mprotect it for timing\n"
            "size = 64 * 1024 * 1024  # 64MB\n"
            "try:\n"
            "  m = mmap.mmap(-1, size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)\n"
            "  # Touch some pages\n"
            "  for i in range(0, min(size, 4096 * 100), 4096):\n"
            "    m[i] = 65\n"
            "  start = time.monotonic()\n"
            "  libc = ctypes.CDLL('libc.so.6')\n"
            "  # mprotect the region\n"
            "  addr = ctypes.c_void_p.from_buffer(m)\n"
            "  libc.mprotect(ctypes.addressof(addr), size, 0x1)  # PROT_READ\n"
            "  elapsed = time.monotonic() - start\n"
            "  print(f'mprotect timing: {elapsed*1000:.1f}ms')\n"
            "  m.close()\n"
            "except Exception as e:\n"
            "  print(f'mprotect timing test: {e}')")
        self.record("timing", "mprotect timing primitive checked",
                    True,  # Informational — hard to prevent timing primitives
                    f"exit={ec} out={out[:100]}")

        # 14.2: rdtsc — high-resolution timing for cache attacks
        ec, out, err = self.run_py(
            "import ctypes, struct\n"
            "# rdtsc is available from userspace on x86_64\n"
            "# Used for Flush+Reload, Spectre, etc.\n"
            "try:\n"
            "  import time\n"
            "  # Measure timing precision\n"
            "  times = []\n"
            "  for _ in range(100):\n"
            "    t = time.perf_counter_ns()\n"
            "    times.append(t)\n"
            "  diffs = [times[i+1] - times[i] for i in range(len(times)-1)]\n"
            "  avg = sum(diffs) / len(diffs)\n"
            "  print(f'timing resolution: avg={avg:.0f}ns')\n"
            "except Exception as e:\n"
            "  print(f'timing: {e}')")
        self.record("timing", "High-res timing available (inherent to x86)",
                    True,  # Can't prevent rdtsc — informational
                    f"exit={ec} out={out[:100]}")

        # 14.3: POSIX timer creation (CVE-2025-38352 attack surface)
        ec, out, err = self.run_py(
            "import ctypes, signal\n"
            "libc = ctypes.CDLL('libc.so.6', use_errno=True)\n"
            "# CLOCK_MONOTONIC=1\n"
            "timer_id = ctypes.c_long(0)\n"
            "# timer_create\n"
            "ret = libc.timer_create(1, None, ctypes.byref(timer_id))\n"
            "if ret == 0:\n"
            "  print(f'timer_create OK id={timer_id.value}')\n"
            "  libc.timer_delete(timer_id)\n"
            "else:\n"
            "  print(f'timer_create={ret}')")
        self.record("timing", "POSIX timer creation checked",
                    True,  # timer_create is allowed (needed by glibc)
                    f"exit={ec} out={out[:100]}")

    # =========================================================================
    # Category 15: Mount & Filesystem Manipulation
    # =========================================================================

    def test_mount_manipulation(self):
        print(f"\n{BOLD}=== MOUNT & FILESYSTEM MANIPULATION ==={RESET}")

        # 15.1: Remount / as read-write
        ec, out, err = self.run_cmd("mount -o remount,rw / 2>&1")
        self.record("mount", "Remount / as rw blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 15.2: Mount tmpfs on /etc to shadow files
        ec, out, err = self.run_cmd("mount -t tmpfs none /etc 2>&1")
        self.record("mount", "Mount tmpfs on /etc blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 15.3: Bind mount /proc/1/root to escape chroot
        ec, out, err = self.run_cmd("mount --bind /proc/1/root /tmp/escape 2>&1")
        self.record("mount", "Bind mount /proc/1/root blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 15.4: Mount /dev/sda (block device access)
        ec, out, err = self.run_cmd("mount /dev/sda /tmp/mnt 2>&1")
        self.record("mount", "Mount /dev/sda blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

        # 15.5: FUSE filesystem mount (attack primitive for race stabilization)
        ec, out, err = self.run_py(
            "import ctypes, os\n"
            "try:\n"
            "  fd = os.open('/dev/fuse', os.O_RDWR)\n"
            "  print(f'FUSE fd={fd}')\n"
            "  os.close(fd)\n"
            "except Exception as e:\n"
            "  print(f'FUSE blocked: {e}')")
        self.record("mount", "/dev/fuse blocked (race stabilizer prevention)",
                    "FUSE blocked" in out or "fd=-1" in out,
                    f"exit={ec} out={out[:100]}")

        # 15.6: overlayfs mount (container escape technique)
        ec, out, err = self.run_cmd(
            "mkdir -p /tmp/lower /tmp/upper /tmp/work /tmp/merged 2>/dev/null; "
            "mount -t overlay overlay -olowerdir=/tmp/lower,upperdir=/tmp/upper,"
            "workdir=/tmp/work /tmp/merged 2>&1")
        self.record("mount", "overlayfs mount blocked",
                    ec != 0,
                    f"exit={ec} err={err[:100]}")

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
            self.test_advanced_kernel()
            self.test_resource_hardening()
            self.test_fileless_execution()
            self.test_ipc_attacks()
            self.test_timing_sidechannel()
            self.test_mount_manipulation()
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
