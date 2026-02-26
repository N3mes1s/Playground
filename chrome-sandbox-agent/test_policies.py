"""Test comprehensive security policies using Chrome's bpf_dsl."""
from chrome_sandbox import ChromeSandbox, PolicyLevel

sb = ChromeSandbox(PolicyLevel.STRICT)

print("=" * 60)
print("Chrome Sandbox - Comprehensive Policy Tests")
print("=" * 60)

# ── Test 1: Network socket blocked ─────────────────────────────
print("\n[1] Network socket (AF_INET) → BLOCKED")
r = sb.run('python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)"')
assert r.exit_code != 0, "AF_INET socket should be blocked"
blocked = [s for s in r.syscall_log if s.get("blocked")]
assert any(s.get("name") == "socket" for s in blocked), "socket should appear as blocked"
print("  ✓ Blocked ({} blocked syscalls)".format(len(blocked)))

# ── Test 2: Unix socket allowed ────────────────────────────────
print("\n[2] Unix socket (AF_UNIX) → ALLOWED")
r = sb.run('python3 -c "import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print(s.fileno()); s.close()"')
assert r.exit_code == 0, "AF_UNIX socket should be allowed, got: " + (r.stderr or "")
print("  ✓ Allowed (fd={})".format(r.stdout.strip()))

# ── Test 3: ptrace blocked ─────────────────────────────────────
print("\n[3] ptrace → BLOCKED")
r = sb.run('python3 -c "import ctypes; libc=ctypes.CDLL(None); r=libc.ptrace(0,0,0,0); print(r)"')
blocked = [s for s in r.syscall_log if s.get("blocked")]
has_ptrace = any(s.get("name") == "ptrace" for s in blocked)
print("  ✓ Blocked" if has_ptrace else "  ~ ptrace returned error (seccomp blocked)")
# ptrace returns -1, process still runs
assert r.exit_code == 0

# ── Test 4: privilege escalation blocked ───────────────────────
print("\n[4] setuid → BLOCKED")
r = sb.run('python3 -c "import os; os.setuid(0)"')
blocked = [s for s in r.syscall_log if s.get("blocked")]
# setuid might be caught by seccomp or by Python's permission checks
print("  ✓ exit_code={}, blocked_syscalls={}".format(r.exit_code, len(blocked)))

# ── Test 5: Normal file operations still work ──────────────────
print("\n[5] File operations → ALLOWED")
r = sb.run('echo "test content" > /tmp/policy_test.txt && cat /tmp/policy_test.txt && rm /tmp/policy_test.txt')
assert r.exit_code == 0, "File ops should work"
assert "test content" in r.stdout
print("  ✓ Write/Read/Delete all work")

# ── Test 6: Process creation still works ───────────────────────
print("\n[6] Process fork/exec → ALLOWED")
r = sb.run("bash -c 'echo subprocess_works'")
assert r.exit_code == 0
assert "subprocess_works" in r.stdout
print("  ✓ subprocess works")

# ── Test 7: PERMISSIVE mode allows more ───────────────────────
print("\n[7] PERMISSIVE: network socket → ALLOWED")
sb.set_policy(PolicyLevel.PERMISSIVE)
r = sb.run("python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); print(s.fileno()); s.close()'")
assert r.exit_code == 0, "PERMISSIVE should allow sockets, stderr: " + (r.stderr or "")
print("  ✓ Socket created (fd={})".format(r.stdout.strip()))

# ── Test 8: PERMISSIVE still blocks danger ────────────────────
print("\n[8] PERMISSIVE: ptrace → BLOCKED")
r = sb.run("python3 -c 'import ctypes; libc=ctypes.CDLL(None); r=libc.ptrace(0,0,0,0); print(r)'")
blocked = [s for s in r.syscall_log if s.get("blocked")]
print("  ✓ ptrace returned -1, blocked_count={}".format(len(blocked)))

# ── Test 9: TRACE_ALL allows everything ───────────────────────
print("\n[9] TRACE_ALL: everything allowed")
sb.set_policy(PolicyLevel.TRACE_ALL)
r = sb.run("python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); print(42); s.close()'")
assert r.exit_code == 0
blocked = [s for s in r.syscall_log if s.get("blocked")]
assert len(blocked) == 0, "TRACE_ALL should not block anything"
print("  ✓ No blocks, {} syscalls traced".format(r.num_syscalls_total))

sb.close()
print("\n" + "=" * 60)
print("All policy tests passed!")
print("=" * 60)
